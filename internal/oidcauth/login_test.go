package oidcauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/oidctest"
)

func TestLoginDiscoversProviderAndValidatesNonce(t *testing.T) {
	for _, test := range []struct {
		name            string
		nonce           string
		subject         string
		audience        any
		authorizedParty string
		valid           bool
	}{
		{name: "valid", subject: "user-123", valid: true},
		{name: "multiple audiences missing azp", subject: "user-123", audience: []string{"tnl-cli", "other-client"}},
		{name: "multiple audiences wrong azp", subject: "user-123", audience: []string{"tnl-cli", "other-client"}, authorizedParty: "other-client"},
		{name: "multiple audiences correct azp", subject: "user-123", audience: []string{"tnl-cli", "other-client"}, authorizedParty: "tnl-cli", valid: true},
		{name: "single audience wrong azp", subject: "user-123", authorizedParty: "other-client"},
		{name: "single audience correct azp", subject: "user-123", authorizedParty: "tnl-cli", valid: true},
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
					audience := test.audience
					if audience == nil {
						audience = "tnl-cli"
					}
					claims := map[string]any{
						"iss": provider.URL, "sub": test.subject, "aud": audience, "nonce": tokenNonce,
						"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
					}
					if test.authorizedParty != "" {
						claims["azp"] = test.authorizedParty
					}
					idToken := signer.Token(t, "key-1", claims)
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{
						"access_token": "provider-access", "refresh_token": "provider-refresh",
						"token_type": "Bearer", "expires_in": 300, "refresh_expires_in": 3600, "id_token": idToken,
					})
				default:
					http.NotFound(w, r)
				}
			}))
			defer provider.Close()

			var output bytes.Buffer
			result, err := Login(context.Background(), Config{
				Issuer: provider.URL, ClientID: "tnl-cli", LoginFlow: LoginFlowDeviceCode,
				Scopes: []string{"openid"}, HTTPClient: provider.Client(),
			}, &output)
			if test.valid && (err != nil || result.IDToken == "" || result.Issuer != provider.URL ||
				result.ClientID != "tnl-cli" || result.Subject != "user-123" ||
				result.AccessToken != "provider-access" || result.RefreshToken != "provider-refresh" ||
				result.IDTokenExpiresAt.IsZero() || result.AccessExpiresAt.IsZero() || result.RefreshExpiresAt.IsZero() ||
				!strings.Contains(output.String(), "ABCD-1234")) {
				t.Fatalf("result = %#v, output = %q, error = %v", result, output.String(), err)
			}
			if !test.valid && err == nil {
				t.Fatal("invalid token accepted")
			}
		})
	}
}

func TestAuthorizationCodePKCELogin(t *testing.T) {
	signer := oidctest.NewSigner(t)
	var nonce, challenge, redirectURI string
	var provider *httptest.Server
	provider = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(response).Encode(map[string]any{
				"issuer": provider.URL, "jwks_uri": provider.URL + "/jwks",
				"authorization_endpoint": provider.URL + "/authorize", "token_endpoint": provider.URL + "/token",
			})
		case "/jwks":
			_ = json.NewEncoder(response).Encode(map[string]any{"keys": []any{signer.JWK("key-1")}})
		case "/authorize":
			nonce = request.URL.Query().Get("nonce")
			challenge = request.URL.Query().Get("code_challenge")
			redirectURI = request.URL.Query().Get("redirect_uri")
			if request.URL.Query().Get("code_challenge_method") != "S256" || nonce == "" || challenge == "" {
				t.Errorf("authorization query = %v", request.URL.Query())
			}
			redirect := redirectURI + "?code=authorization-code&state=" + request.URL.Query().Get("state")
			http.Redirect(response, request, redirect, http.StatusFound)
		case "/token":
			if err := request.ParseForm(); err != nil {
				t.Error(err)
			}
			verifierHash := sha256.Sum256([]byte(request.Form.Get("code_verifier")))
			if request.Form.Get("code") != "authorization-code" || request.Form.Get("redirect_uri") != redirectURI ||
				base64.RawURLEncoding.EncodeToString(verifierHash[:]) != challenge {
				t.Errorf("token form = %v", request.Form)
			}
			now := time.Now()
			idToken := signer.Token(t, "key-1", map[string]any{
				"iss": provider.URL, "sub": "user-123", "aud": "tnl-cli", "nonce": nonce,
				"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
			})
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(map[string]any{
				"access_token": "provider-access", "refresh_token": "provider-refresh",
				"token_type": "Bearer", "expires_in": 300, "refresh_token_expires_in": 3600, "id_token": idToken,
			})
		default:
			http.NotFound(response, request)
		}
	}))
	defer provider.Close()
	client := provider.Client()
	var output bytes.Buffer
	result, err := Login(context.Background(), Config{
		Issuer: provider.URL, ClientID: "tnl-cli", LoginFlow: LoginFlowAuthorizationCodePKCE,
		Scopes: []string{"openid"}, HTTPClient: client,
		OpenURL: func(target string) error {
			authorizationURL, err := url.Parse(target)
			if err != nil {
				return err
			}
			invalidCallback := authorizationURL.Query().Get("redirect_uri") + "?code=ignored&state=invalid"
			response, err := client.Get(invalidCallback)
			if err != nil {
				return err
			}
			if closeErr := response.Body.Close(); closeErr != nil {
				return closeErr
			}
			if response.StatusCode != http.StatusBadRequest {
				return fmt.Errorf("invalid callback status = %d", response.StatusCode)
			}
			response, err = client.Get(target)
			if err == nil {
				err = response.Body.Close()
			}
			return err
		},
	}, &output)
	if err != nil || result.IDToken == "" || result.AccessToken != "provider-access" ||
		result.RefreshToken != "provider-refresh" || result.RefreshExpiresAt.IsZero() || result.Subject != "user-123" ||
		!strings.Contains(output.String(), provider.URL+"/authorize") {
		t.Fatalf("result = %#v, output = %q, error = %v", result, output.String(), err)
	}
}

func TestLoginRequiresExplicitOpenIDScopes(t *testing.T) {
	for _, scopes := range [][]string{nil, {}, {"operations"}, {"openid", "openid"}} {
		if _, err := Login(context.Background(), Config{
			Issuer: "https://issuer.example", ClientID: "tnl-cli", LoginFlow: LoginFlowDeviceCode, Scopes: scopes,
		}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "invalid configuration") {
			t.Fatalf("scopes %v error = %v", scopes, err)
		}
	}
}
