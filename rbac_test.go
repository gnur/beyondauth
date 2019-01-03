package main

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/gnur/beyondauth/jwt"
)

func getHTTPrequest(token string, headers map[string]string) *http.Request {
	buf := new(bytes.Buffer)
	r, _ := http.NewRequest("GET", "localhost", buf)
	c := http.Cookie{
		Name:  "x-beyond-auth",
		Value: token,
	}
	r.AddCookie(&c)
	for n, v := range headers {
		r.Header.Set(n, v)
	}
	return r
}

func getToken(user, expires string) string {
	expireTime, err := time.ParseDuration(expires)
	if err != nil {
		expireTime = 5 * time.Minute
	}

	token, _ := jwt.NewToken(user, expireTime)
	return token
}

func Test_requestAllowed(t *testing.T) {
	var authConfig Conf
	loadConfig(&authConfig, "example.toml", true)
	type args struct {
		rules *Conf
		r     *http.Request
	}
	type requestAllowedTest struct {
		name        string
		args        args
		wantAllowed bool
	}
	tests := []requestAllowedTest{
		requestAllowedTest{
			name: "user valid but wrong group",
			args: args{
				rules: &authConfig,
				r: getHTTPrequest(
					getToken("test@example.com", "10s"),
					map[string]string{
						"x-forwarded-for":  "1.1.0.12",
						"x-forwarded-host": "superprivate.docker.localhost",
					},
				),
			},
			wantAllowed: false,
		},
		requestAllowedTest{
			name: "user valid and correct group",
			args: args{
				rules: &authConfig,
				r: getHTTPrequest(
					getToken("test@example.com", "10s"),
					map[string]string{
						"x-forwarded-for":  "1.1.1.12",
						"x-forwarded-host": "private.docker.localhost",
					},
				),
			},
			wantAllowed: true,
		},
		requestAllowedTest{
			name: "valid user with expired token",
			args: args{
				rules: &authConfig,
				r: getHTTPrequest(
					getToken("erwin@example.com", "-10s"),
					map[string]string{
						"x-forwarded-for":  "1.1.1.12",
						"x-forwarded-host": "private.docker.localhost",
					},
				),
			},
			wantAllowed: false,
		},
		requestAllowedTest{
			name: "public domain",
			args: args{
				rules: &authConfig,
				r: getHTTPrequest(
					getToken("test@example.com", "-10s"),
					map[string]string{
						"x-forwarded-for":  "1.1.4.12",
						"x-forwarded-host": "public.docker.localhost",
					},
				),
			},
			wantAllowed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAllowed, _ := authConfig.requestAllowed(tt.args.r)
			if gotAllowed != tt.wantAllowed {
				t.Errorf("requestAllowed() gotAllowed = %v, want %v", gotAllowed, tt.wantAllowed)
			}
		})
	}
}
