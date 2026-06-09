package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/oidctest"
)

func TestOIDCVerifierValidatesClaimsAndCachesJWKS(t *testing.T) {
	signer := oidctest.NewSigner(t)
	var jwksAvailable atomic.Bool
	jwksAvailable.Store(true)
	var provider *httptest.Server
	provider = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 provider.URL,
				"jwks_uri":               provider.URL + "/jwks",
				"authorization_endpoint": provider.URL + "/authorize",
				"token_endpoint":         provider.URL + "/token",
			})
		case "/jwks":
			if !jwksAvailable.Load() {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{signer.JWK("key-1")}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	verifier, err := NewOIDCVerifier(OIDCConfig{
		Issuer: provider.URL, ClientID: "tnl-cli", HTTPClient: provider.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	nonce := "verified-nonce"
	claims := map[string]any{
		"iss": provider.URL, "sub": "user-123", "aud": "tnl-cli",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": nonce,
	}
	raw := signer.Token(t, "key-1", claims)
	identity, err := verifier.Verify(context.Background(), raw)
	if err != nil || identity.Subject != "user-123" || identity.Issuer != provider.URL ||
		identity.AssertionIdentity != provider.URL+"\x00"+nonce {
		t.Fatalf("identity = %#v, error = %v", identity, err)
	}

	for _, test := range []struct {
		name            string
		audience        any
		authorizedParty string
		valid           bool
	}{
		{name: "multiple audiences missing azp", audience: []string{"tnl-cli", "other-client"}},
		{name: "multiple audiences wrong azp", audience: []string{"tnl-cli", "other-client"}, authorizedParty: "other-client"},
		{name: "multiple audiences correct azp", audience: []string{"tnl-cli", "other-client"}, authorizedParty: "tnl-cli", valid: true},
		{name: "single audience wrong azp", audience: "tnl-cli", authorizedParty: "other-client"},
		{name: "single audience correct azp", audience: "tnl-cli", authorizedParty: "tnl-cli", valid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims["aud"] = test.audience
			delete(claims, "azp")
			if test.authorizedParty != "" {
				claims["azp"] = test.authorizedParty
			}
			_, err := verifier.Verify(context.Background(), signer.Token(t, "key-1", claims))
			if test.valid && err != nil {
				t.Fatalf("correct azp error = %v", err)
			}
			if !test.valid && !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("invalid azp error = %v", err)
			}
		})
	}
	claims["aud"] = "tnl-cli"
	delete(claims, "azp")
	jwksAvailable.Store(false)
	if _, err := verifier.Verify(context.Background(), raw); err != nil {
		t.Fatalf("cached key failed during outage: %v", err)
	}
	unknownSigner := oidctest.NewSigner(t)
	if _, err := verifier.Verify(context.Background(), unknownSigner.Token(t, "key-2", claims)); !errors.Is(err, ErrOIDCUnavailable) {
		t.Fatalf("unknown key outage error = %v", err)
	}

	claims["aud"] = "other-client"
	if _, err := verifier.Verify(context.Background(), signer.Token(t, "key-1", claims)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("audience error = %v", err)
	}
}

func TestOIDCVerifierDoesNotDiscoverAtStartup(t *testing.T) {
	verifier, err := NewOIDCVerifier(OIDCConfig{Issuer: "https://offline.example", ClientID: "tnl-cli"})
	if err != nil || verifier == nil {
		t.Fatalf("verifier = %#v, error = %v", verifier, err)
	}
}
