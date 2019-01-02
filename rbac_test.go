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
	var authConfig BeyondauthConfig
	loadConfig(&authConfig, "rbac.toml")
	type args struct {
		rules *BeyondauthConfig
		r     *http.Request
	}
	type requestAllowedTest struct {
		name        string
		args        args
		wantAllowed bool
		wantReason  string
		wantUser    string
	}
	tests := []requestAllowedTest{
		requestAllowedTest{
			name: "ip in subnet",
			args: args{
				rules: &authConfig,
				r: getHTTPrequest(
					getToken("user@example.com", "10s"),
					map[string]string{
						"x-forwarded-for":  "1.1.0.12",
						"x-forwarded-host": "example.com",
					},
				),
			},
			wantAllowed: true,
			wantReason:  "user in valid group",
			wantUser:    "",
		},
		requestAllowedTest{
			name: "ip not in subnet",
			args: args{
				rules: &authConfig,
				r: getHTTPrequest(
					getToken("user@example.com", "10s"),
					map[string]string{
						"x-forwarded-for":  "1.1.1.12",
						"x-forwarded-host": "example.com",
					},
				),
			},
			wantAllowed: false,
			wantReason:  "default",
			wantUser:    "",
		},
		requestAllowedTest{
			name: "invalid ip",
			args: args{
				rules: &authConfig,
				r: getHTTPrequest(
					getToken("user@example.com", "10s"),
					map[string]string{
						"x-forwarded-for":  "1.1.12",
						"x-forwarded-host": "example.com",
					},
				),
			},
			wantAllowed: false,
			wantReason:  "invalid ip",
			wantUser:    "",
		},
		requestAllowedTest{
			name: "user valid but wrong group",
			args: args{
				rules: &authConfig,
				r: getHTTPrequest(
					getToken("user@example.com", "10s"),
					map[string]string{
						"x-forwarded-for":  "1.1.0.12",
						"x-forwarded-host": "supersecret.example.com",
					},
				),
			},
			wantAllowed: false,
			wantReason:  "default",
			wantUser:    "",
		},
		requestAllowedTest{
			name: "user valid and correct group",
			args: args{
				rules: &authConfig,
				r: getHTTPrequest(
					getToken("erwin@example.com", "10s"),
					map[string]string{
						"x-forwarded-for":  "1.1.1.12",
						"x-forwarded-host": "supersecret.example.com",
					},
				),
			},
			wantAllowed: true,
			wantReason:  "user in valid group",
			wantUser:    "",
		},
		requestAllowedTest{
			name: "not public subdomain with valid ip",
			args: args{
				rules: &authConfig,
				r: getHTTPrequest(
					getToken("erwin@example.com", "10s"),
					map[string]string{
						"x-forwarded-for":  "1.1.0.12",
						"x-forwarded-host": "test.private.example.com",
					},
				),
			},
			wantAllowed: true,
			wantReason:  "user in valid group",
			wantUser:    "",
		},
		requestAllowedTest{
			name: "not public subdomain with invalid ip",
			args: args{
				rules: &authConfig,
				r: getHTTPrequest(
					getToken("erwin@example.com", "10s"),
					map[string]string{
						"x-forwarded-for":  "1.1.1.12",
						"x-forwarded-host": "other.private.example.com",
					},
				),
			},
			wantAllowed: false,
			wantReason:  "default",
			wantUser:    "",
		},
		requestAllowedTest{
			name: "valid user with expired token",
			args: args{
				rules: &authConfig,
				r: getHTTPrequest(
					getToken("erwin@example.com", "-10s"),
					map[string]string{
						"x-forwarded-for":  "1.1.1.12",
						"x-forwarded-host": "supersecret.example.com",
					},
				),
			},
			wantAllowed: false,
			wantReason:  "default",
			wantUser:    "",
		},
		requestAllowedTest{
			name: "public subdomain",
			args: args{
				rules: &authConfig,
				r: getHTTPrequest(
					getToken("erwin@example.com", "-10s"),
					map[string]string{
						"x-forwarded-for":  "1.1.4.12",
						"x-forwarded-host": "other.public.example.com",
					},
				),
			},
			wantAllowed: true,
			wantReason:  "host is public",
			wantUser:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAllowed, gotReason, _ := requestAllowed(tt.args.rules, tt.args.r)
			if gotAllowed != tt.wantAllowed || gotReason != tt.wantReason {
				t.Errorf("requestAllowed() gotAllowed = %v, want %v, reason %v", gotAllowed, tt.wantAllowed, gotReason)
			}
		})
	}
}
