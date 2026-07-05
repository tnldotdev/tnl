package oidcauth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/oidctest"
)

func TestVerifierAuthenticatesBoundedAuth0Identity(t *testing.T) {
	signer := oidctest.NewSigner(t)
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
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(func() {
		provider.CloseClientConnections()
		provider.Close()
	})
	verifier, err := NewVerifier(VerifierConfig{Issuer: provider.URL, ClientID: "tnl-cli", HTTPClient: provider.Client()})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	raw := signer.Token(t, "key-1", map[string]any{
		"iss": provider.URL, "sub": "auth0|subject", "aud": []string{"tnl-cli", "auth0-api"},
		"azp": "tnl-cli", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": "nonce",
		"name": "Example User", "email": " USER@example.com ", "email_verified": true,
	})
	identity, err := verifier.Verify(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Issuer != provider.URL || identity.Subject != "auth0|subject" || identity.DisplayName != "Example User" ||
		identity.NormalizedEmail != "user@example.com" || !identity.EmailVerified || identity.Nonce != "nonce" ||
		identity.AssertionDigest != sha256.Sum256([]byte(raw)) || identity.ExpiresAt.IsZero() {
		t.Fatalf("identity = %#v", identity)
	}
}

func TestVerifierDiscoversPathBasedIssuer(t *testing.T) {
	signer := oidctest.NewSigner(t)
	var provider *httptest.Server
	provider = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		issuer := provider.URL + "/realms/company"
		switch request.URL.Path {
		case "/realms/company/.well-known/openid-configuration":
			_ = json.NewEncoder(response).Encode(map[string]any{
				"issuer": issuer, "jwks_uri": provider.URL + "/jwks",
				"authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token",
			})
		case "/jwks":
			_ = json.NewEncoder(response).Encode(map[string]any{"keys": []any{signer.JWK("key-1")}})
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(func() {
		provider.CloseClientConnections()
		provider.Close()
	})
	issuer := provider.URL + "/realms/company"
	verifier, err := NewVerifier(VerifierConfig{Issuer: issuer, ClientID: "tnl-cli", HTTPClient: provider.Client()})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	raw := signer.Token(t, "key-1", map[string]any{
		"iss": issuer, "sub": "subject", "aud": "tnl-cli", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	identity, err := verifier.Verify(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Issuer != issuer || identity.Subject != "subject" {
		t.Fatalf("identity = %#v", identity)
	}
}

func TestVerifierRejectsInvalidIdentityClaims(t *testing.T) {
	signer := oidctest.NewSigner(t)
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
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(func() {
		provider.CloseClientConnections()
		provider.Close()
	})
	verifier, err := NewVerifier(VerifierConfig{Issuer: provider.URL, ClientID: "tnl-cli", HTTPClient: provider.Client()})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, test := range []struct {
		name   string
		claims map[string]any
	}{
		{name: "missing subject", claims: map[string]any{"aud": "tnl-cli"}},
		{name: "wrong authorized party", claims: map[string]any{"sub": "subject", "aud": "tnl-cli", "azp": "other"}},
		{name: "multiple audiences missing authorized party", claims: map[string]any{"sub": "subject", "aud": []string{"tnl-cli", "other"}}},
		{name: "invalid verified email", claims: map[string]any{"sub": "subject", "aud": "tnl-cli", "email": "invalid", "email_verified": true}},
		{name: "expired", claims: map[string]any{"sub": "subject", "aud": "tnl-cli", "exp": now.Add(-time.Minute).Unix()}},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := map[string]any{"iss": provider.URL, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
			for key, value := range test.claims {
				claims[key] = value
			}
			raw := signer.Token(t, "key-1", claims)
			if _, err := verifier.Verify(t.Context(), raw); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestVerifierMapsDiscoveryFailureToUnavailable(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})}
	verifier, err := NewVerifier(VerifierConfig{Issuer: "https://issuer.example", ClientID: "tnl-cli", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(t.Context(), "header.payload.signature"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v", err)
	}
}

func TestNewVerifierRejectsInvalidConfiguration(t *testing.T) {
	if _, err := NewVerifier(VerifierConfig{
		Issuer: "https://issuer.example/realms/company", ClientID: "client",
	}); err != nil {
		t.Fatalf("path-based issuer: %v", err)
	}

	for _, config := range []VerifierConfig{
		{},
		{Issuer: "http://issuer.example", ClientID: "client"},
		{Issuer: "https://user@issuer.example/path", ClientID: "client"},
		{Issuer: "https://issuer.example/path?tenant=company", ClientID: "client"},
		{Issuer: "https://issuer.example/path#company", ClientID: "client"},
		{Issuer: "https://issuer.example", ClientID: ""},
	} {
		if _, err := NewVerifier(config); err == nil {
			t.Fatalf("accepted config %#v", config)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
