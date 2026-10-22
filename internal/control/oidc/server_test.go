package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"

	"golang.org/x/oauth2"
)

func TestStandardServerProviderProfiles(t *testing.T) {
	for _, profile := range []struct {
		name, path, client, secret string
		basic                      bool
	}{
		{"generic-public-pkce", "", "public-client", "", false},
		{"generic-default-basic", "", "server-client", "server-secret", true},
		{"google-web-client", "", "123.apps.googleusercontent.com", "google-secret", false},
		{"entra-tenant", "/12345678-1234-1234-1234-123456789abc/v2.0", "12345678-1234-1234-1234-123456789abc", "entra-secret", false},
		{"hosted-oidc-broker", "", "tnl-control", "broker-secret", false},
	} {
		t.Run(profile.name, func(t *testing.T) {
			p := newTestProvider(t, profile.path)
			if !profile.basic {
				p.authMethods = []string{"client_secret_post", "none"}
			}
			const nonce = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			verifier := oauth2.GenerateVerifier()
			raw := p.signer.Token(t, "key-1", map[string]any{"iss": p.issuer, "sub": "named-subject", "aud": profile.client, "nonce": nonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
			p.mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Error(err)
					http.Error(w, "bad form", 400)
					return
				}
				client, secret := r.Form.Get("client_id"), r.Form.Get("client_secret")
				if profile.basic {
					client, secret, _ = r.BasicAuth()
				}
				if client != profile.client || secret != profile.secret || r.Form.Get("code_verifier") != verifier || r.Form.Get("redirect_uri") != "https://control.example/v1/auth/device/callback" || r.Form.Get("code") != "one-use-code" || r.Form.Get("grant_type") != "authorization_code" {
					t.Error("server client did not bind the code exchange")
					http.Error(w, "bad request", 400)
					return
				}
				writeProviderJSON(t, w, map[string]any{"id_token": raw, "access_token": "unused", "token_type": "Bearer"})
			})
			s, err := NewServer(ServerConfig{Issuer: p.issuer, ClientID: profile.client, ClientSecret: profile.secret, RedirectURL: "https://control.example/v1/auth/device/callback", Scopes: []string{"openid", "profile", "email"}, HTTPClient: p.client})
			if err != nil {
				t.Fatal(err)
			}
			authorization, err := s.AuthorizationURL(t.Context(), strings.Repeat("s", 43), nonce, verifier)
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(authorization)
			if err != nil {
				t.Fatal(err)
			}
			q := u.Query()
			digest := sha256.Sum256([]byte(verifier))
			if q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(digest[:]) || q.Get("code_challenge_method") != "S256" || q.Get("nonce") != nonce || q.Get("response_type") != "code" || q.Get("scope") != "openid profile email" {
				t.Fatal("authorization was not standard code+PKCE")
			}
			identity, err := s.Redeem(t.Context(), "one-use-code", nonce, verifier)
			if err != nil || identity.Subject != "named-subject" || len(identity.TeamContexts) != 0 {
				t.Fatalf("identity: %#v %v", identity, err)
			}
			if _, err := s.Redeem(t.Context(), "one-use-code", strings.Repeat("b", 43), verifier); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("wrong nonce: %v", err)
			}
		})
	}
}

func TestServerOwnsProviderFailureClassification(t *testing.T) {
	for _, tt := range []struct {
		status int
		body   any
		want   error
	}{{400, map[string]string{"error": "invalid_grant"}, ErrUnauthenticated}, {400, map[string]string{"error": "access_denied"}, ErrUnauthenticated}, {503, map[string]string{"error": "temporarily_unavailable"}, ErrUnavailable}, {503, map[string]string{"error": "invalid_grant"}, ErrUnavailable}, {200, map[string]string{"access_token": "provider-secret", "token_type": "Bearer"}, ErrUnavailable}, {200, map[string]string{"id_token": "", "access_token": "provider-secret", "token_type": "Bearer"}, ErrUnavailable}} {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			p := newTestProvider(t, "")
			p.mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Traceparent") != "" {
					t.Error("identity provider received tnl trace propagation")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				writeProviderJSON(t, w, tt.body)
			})
			s, err := NewServer(ServerConfig{Issuer: p.issuer, ClientID: "server", RedirectURL: "https://control.example/callback", Scopes: []string{"openid"}, HTTPClient: p.client})
			if err != nil {
				t.Fatal(err)
			}
			metrics := observability.New("control")
			t.Cleanup(func() { _ = metrics.Shutdown(t.Context()) })
			if _, err := s.Redeem(observability.WithMetrics(t.Context(), metrics), "one-use-code", strings.Repeat("n", 43), oauth2.GenerateVerifier()); !errors.Is(err, tt.want) {
				t.Fatalf("classification: %v", err)
			}
			w := httptest.NewRecorder()
			metrics.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
			outcome := "error"
			if tt.want == ErrUnauthenticated {
				outcome = "denied"
			}
			if !strings.Contains(w.Body.String(), `tnl_control_operation_duration_seconds_count{tnl_operation="oidc.redeem",tnl_outcome="`+outcome+`"} 1`) || strings.Contains(w.Body.String(), "provider-secret") {
				t.Fatal("provider failure metric lost bounded classification")
			}
		})
	}
}

func TestVerifierPreservesExactIssuerTrailingSlash(t *testing.T) {
	p := newTestProvider(t, "")
	p.issuer += "/"
	v, err := NewVerifier(VerifierConfig{Issuer: p.issuer, ClientID: "server", HTTPClient: p.client})
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"iss": p.issuer, "sub": "named-subject", "aud": "server", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	if _, err := v.Verify(t.Context(), p.signer.Token(t, "key-1", claims)); err != nil {
		t.Fatal(err)
	}
	claims["iss"] = strings.TrimSuffix(p.issuer, "/")
	if _, err := v.Verify(t.Context(), p.signer.Token(t, "key-1", claims)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("issuer spelling was normalized: %v", err)
	}
}
