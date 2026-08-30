package oidclogin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/oidctest"
)

func TestLoginDiscoversProviderAndValidatesNonce(t *testing.T) {
	for _, test := range []struct {
		name    string
		nonce   string
		subject string
		valid   bool
	}{
		{name: "valid", subject: "user-123", valid: true},
		{name: "nonce mismatch", nonce: "wrong", subject: "user-123"},
		{name: "missing subject"},
	} {
		t.Run(test.name, func(t *testing.T) {
			signer := oidctest.NewSigner(t)
			var mu sync.Mutex
			nonce := ""
			var provider *httptest.Server
			provider = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					_ = json.NewEncoder(w).Encode(map[string]any{
						"issuer":                        provider.URL,
						"jwks_uri":                      provider.URL + "/jwks",
						"authorization_endpoint":        provider.URL + "/authorize",
						"device_authorization_endpoint": provider.URL + "/device",
						"token_endpoint":                provider.URL + "/token",
					})
				case "/jwks":
					_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{signer.JWK("key-1")}})
				case "/device":
					if err := r.ParseForm(); err != nil {
						t.Error(err)
					}
					mu.Lock()
					nonce = r.Form.Get("nonce")
					mu.Unlock()
					_ = json.NewEncoder(w).Encode(map[string]any{
						"device_code": "device-code", "user_code": "ABCD-1234",
						"verification_uri": provider.URL + "/device-login", "expires_in": 60, "interval": 1,
					})
				case "/token":
					if authorization := r.Header.Get("Authorization"); authorization != "" {
						t.Errorf("token authorization header = %q", authorization)
					}
					if err := r.ParseForm(); err != nil {
						t.Error(err)
					}
					if clientID := r.Form.Get("client_id"); clientID != "tnl-cli" {
						t.Errorf("token client_id = %q", clientID)
					}
					mu.Lock()
					tokenNonce := nonce
					mu.Unlock()
					if test.nonce != "" {
						tokenNonce = test.nonce
					}
					now := time.Now()
					idToken := signer.Token(t, "key-1", map[string]any{
						"iss": provider.URL, "sub": test.subject, "aud": "tnl-cli", "nonce": tokenNonce,
						"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
					})
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{
						"access_token": "unused", "token_type": "Bearer", "expires_in": 300, "id_token": idToken,
					})
				default:
					http.NotFound(w, r)
				}
			}))
			defer provider.Close()

			var output bytes.Buffer
			token, err := Login(context.Background(), Config{
				Issuer: provider.URL, ClientID: "tnl-cli", HTTPClient: provider.Client(),
			}, &output)
			if test.valid && (err != nil || token == "" || !strings.Contains(output.String(), "ABCD-1234")) {
				t.Fatalf("token = %q, output = %q, error = %v", token, output.String(), err)
			}
			if !test.valid && err == nil {
				t.Fatal("invalid token accepted")
			}
		})
	}
}
