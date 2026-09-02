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

	"github.com/tnldotdev/tnl/internal/oidcnonce"
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

	const coreEndpoint = "https://core-a.example"
	nonce, err := oidcnonce.New(coreEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewOIDCVerifier(OIDCConfig{
		Issuer: provider.URL, ClientID: "tnl-cli", CoreEndpoint: coreEndpoint, HTTPClient: provider.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := map[string]any{
		"iss": provider.URL, "sub": "user-123", "aud": "tnl-cli",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": nonce,
	}
	raw := signer.Token(t, "key-1", claims)
	identity, err := verifier.Verify(context.Background(), raw)
	if err != nil || identity.Subject != "user-123" || identity.Issuer != provider.URL {
		t.Fatalf("identity = %#v, error = %v", identity, err)
	}

	otherCore, err := NewOIDCVerifier(OIDCConfig{
		Issuer: provider.URL, ClientID: "tnl-cli", CoreEndpoint: "https://core-b.example", HTTPClient: provider.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherCore.Verify(context.Background(), raw); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("cross-Core nonce error = %v", err)
	}
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
	verifier, err := NewOIDCVerifier(OIDCConfig{
		Issuer: "https://offline.example", ClientID: "tnl-cli", CoreEndpoint: "https://core.example",
	})
	if err != nil || verifier == nil {
		t.Fatalf("verifier = %#v, error = %v", verifier, err)
	}
}
