package oidcauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestVerifierAuthenticatesBoundedAuth0Identity(t *testing.T) {
	p := newTestProvider(t, "")
	verifier, err := NewVerifier(VerifierConfig{Issuer: p.issuer, ClientID: "tnl-cli", HTTPClient: p.client})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	raw := p.signer.Token(t, "key-1", map[string]any{
		"iss": p.issuer, "sub": "auth0|subject", "aud": []string{"tnl-cli", "auth0-api"},
		"azp": "tnl-cli", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": "nonce",
		"name": "Example User", "email": " USER@example.com ", "email_verified": true,
	})
	identity, err := verifier.Verify(loginTestContext(t), raw)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Issuer != p.issuer || identity.Subject != "auth0|subject" || identity.DisplayName != "Example User" ||
		identity.NormalizedEmail != "user@example.com" || !identity.EmailVerified || identity.Nonce != "nonce" ||
		identity.AssertionDigest != sha256.Sum256([]byte(raw)) || identity.ExpiresAt.IsZero() {
		t.Fatalf("identity = %#v", identity)
	}
}

func TestVerifierDiscoversPathBasedIssuer(t *testing.T) {
	p := newTestProvider(t, "/realms/company")
	issuer := p.issuer
	verifier, err := NewVerifier(VerifierConfig{Issuer: issuer, ClientID: "tnl-cli", HTTPClient: p.client})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	raw := p.signer.Token(t, "key-1", map[string]any{
		"iss": issuer, "sub": "subject", "aud": "tnl-cli", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	identity, err := verifier.Verify(loginTestContext(t), raw)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Issuer != issuer || identity.Subject != "subject" {
		t.Fatalf("identity = %#v", identity)
	}
}

func TestVerifierRejectsInvalidIdentityClaims(t *testing.T) {
	p := newTestProvider(t, "")
	verifier, err := NewVerifier(VerifierConfig{Issuer: p.issuer, ClientID: "tnl-cli", HTTPClient: p.client})
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
			claims := map[string]any{"iss": p.issuer, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
			for key, value := range test.claims {
				claims[key] = value
			}
			raw := p.signer.Token(t, "key-1", claims)
			if _, err := verifier.Verify(loginTestContext(t), raw); !errors.Is(err, ErrUnauthenticated) {
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
