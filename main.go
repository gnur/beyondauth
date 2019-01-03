//  BeyondAuth, a utility to create an IAP from traefik and nginx
//  Copyright (C) 2018 Erwin de Keijzer

//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.

//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.

//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/gnur/beyondauth/jwt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
}

var internalServerErrorText = "internal server error"

type idtc struct {
	Azp        string
	Aud        string
	Sub        string
	Hdstring   string
	Email      string
	Verified   bool   `json:"email_verified"`
	Hash       string `json:"at_hash"`
	Exp        int64
	Iss        string
	Iat        int64
	Name       string
	Picture    string
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Locale     string
}

var (
	confFile = os.Getenv("BEYONDAUTH_RULES_FILE")
)

func main() {
	if confFile == "" {
		log.Info("Could not get config file location from ENV using default: /etc/beyondauthconfig.toml")
		confFile = "/etc/beyondauthconfig.toml"
	}
	conf := &Conf{}

	err := loadConfig(conf, confFile, true)
	if err != nil {
		log.WithField("error", err).Fatal("Could not load config")
		return
	}
	go watchConfig(conf, confFile)

	if conf.Verbose {
		log.SetLevel(log.DebugLevel)
	}

	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, conf.OAuth.ProviderDomain)
	if err != nil {
		log.WithFields(log.Fields{
			"provider": conf.OAuth.ProviderDomain,
			"error":    err,
			"config":   conf,
		}).Fatal("Could not initialize provider")
	}
	oidcConfig := &oidc.Config{
		ClientID: conf.OAuth.ClientID,
	}
	verifier := provider.Verifier(oidcConfig)

	config := oauth2.Config{
		ClientID:     conf.OAuth.ClientID,
		ClientSecret: conf.OAuth.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  conf.Fqdn + "/auth/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("target")
		cookie := http.Cookie{
			Name:     "x-beyond-auth-state",
			Value:    state,
			Domain:   conf.Fqdn,
			HttpOnly: true,
			Secure:   !conf.DisableHTTPS,
			Path:     "/",
		}
		http.SetCookie(w, &cookie)
		http.Redirect(w, r, config.AuthCodeURL(state, oidc.Nonce(conf.OAuth.Nonce)), http.StatusFound)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%q", "ok")
	})

	http.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("x-beyond-auth-state")
		if err != nil {
			log.WithField("error", err).Warning("unable to get cookie")
			http.Error(w, internalServerErrorText, http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("state") != c.Value {
			log.WithFields(log.Fields{
				"cookie_state": c.Value,
				"get_state":    r.URL.Query().Get("state"),
			}).Warning("states did not match")
			http.Error(w, internalServerErrorText, http.StatusBadRequest)
			return
		}
		redirectURL, err := base64.RawURLEncoding.DecodeString(c.Value)
		if err != nil {
			log.WithField("err", err).Warning("Could not decode cookie")
			http.Error(w, internalServerErrorText, http.StatusBadRequest)
			return
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			log.WithField("err", err).Warning("Failed to exchange token")
			http.Error(w, internalServerErrorText, http.StatusInternalServerError)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			log.WithField("err", err).Warning("No id_token field in oauth2 token.")
			http.Error(w, internalServerErrorText, http.StatusInternalServerError)
			return
		}
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			log.WithField("err", err).Warning("Failed to verify ID token")
			http.Error(w, internalServerErrorText, http.StatusInternalServerError)
			return
		}

		oauth2Token.AccessToken = "*REDACTED*"

		resp := struct {
			OAuth2Token   *oauth2.Token
			IDTokenClaims *idtc // ID Token payload is just JSON.
		}{oauth2Token, new(idtc)}

		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			log.WithField("err", err).Warning("could not parse claims")
			http.Error(w, internalServerErrorText, http.StatusInternalServerError)
			return
		}

		token, err := jwt.NewToken(resp.IDTokenClaims.Email, conf.MaxTokenAge.Duration)
		if err != nil {
			log.WithField("err", err).Warning("could not create token")
			http.Error(w, internalServerErrorText, http.StatusInternalServerError)
			return
		}
		cookie := http.Cookie{
			Name:     "x-beyond-auth",
			Value:    token,
			Domain:   conf.CookieScope,
			HttpOnly: true,
			Secure:   !conf.DisableHTTPS,
			Path:     "/",
			Expires:  time.Now().Add(conf.MaxTokenAge.Duration),
		}
		http.SetCookie(w, &cookie)
		log.WithFields(log.Fields{
			"domain":      conf.CookieScope,
			"redirecturl": string(redirectURL),
		}).Debug("setting cookie")

		http.Redirect(w, r, string(redirectURL), http.StatusFound)
	})

	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {

		log.WithFields(log.Fields{
			"x-forwarded-for":   r.Header.Get("x-forwarded-for"),
			"x-forwarded-host":  r.Header.Get("x-forwarded-host"),
			"x-forwarded-uri":   r.Header.Get("x-forwarded-uri"),
			"x-forwarded-proto": r.Header.Get("x-forwarded-proto"),
			"user-agent":        r.Header.Get("user-agent"),
		}).Debug("Incoming request")
		allowed, user := conf.requestAllowed(r)

		if allowed {
			w.Header().Set("X-Auth-User", user)
			fmt.Fprintf(w, "%q", "ok")
			return
		}

		_, err := r.Cookie("x-beyond-auth")
		// cookie is set, so user is logged in
		if err != nil {
			// user is not logged in, authenticate
			host := r.Header.Get("x-forwarded-host")
			uri := r.Header.Get("x-forwarded-uri")
			proto := r.Header.Get("x-forwarded-proto")
			state := base64.RawURLEncoding.EncodeToString([]byte(proto + "://" + host + uri))
			http.Redirect(w, r, conf.Fqdn+"/login?target="+state, http.StatusFound)

			return
		}

		http.Error(w, "access denied", http.StatusForbidden)
		return
	})

	log.Println("Now listening on 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
