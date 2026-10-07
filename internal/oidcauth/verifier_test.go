package oidcauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/oidctest"
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
	failure := errors.New("network failure")
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, failure
	})}
	verifier, err := NewVerifier(VerifierConfig{Issuer: "https://issuer.example", ClientID: "tnl-cli", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(t.Context(), "header.payload.signature"); !errors.Is(err, ErrUnavailable) || !errors.Is(err, failure) {
		t.Fatalf("error = %v", err)
	}
}

func TestVerifierPreservesParentCancellationCause(t *testing.T) {
	cause := errors.New("caller stopped")
	ctx, cancel := context.WithCancelCause(t.Context())
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		cancel(cause)
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	verifier, err := NewVerifier(VerifierConfig{Issuer: "https://issuer.example", ClientID: "tnl-cli", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(ctx, "header.payload.signature"); !errors.Is(err, cause) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v, want caller cause only", err)
	}
}

func TestVerifierDiscoveryWaitHonorsCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		close(started)
		<-release
		return nil, errors.New("discovery failed")
	})}
	verifier, err := NewVerifier(VerifierConfig{Issuer: "https://issuer.example", ClientID: "tnl-cli", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() {
		_, err := verifier.Verify(t.Context(), "header.payload.signature")
		firstDone <- err
	}()
	<-started

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	secondDone := make(chan error, 1)
	go func() {
		_, err := verifier.Verify(ctx, "header.payload.signature")
		secondDone <- err
	}()
	select {
	case err := <-secondDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiting verification = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled verification remained blocked on discovery")
	}
	close(release)
	if err := <-firstDone; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("first verification = %v", err)
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

func TestVerifierDistinguishesKeyFetchFailuresFromInvalidSignatures(t *testing.T) {
	p := newTestProvider(t, "")
	claims := map[string]any{"iss": p.issuer, "sub": "subject", "aud": "tnl-cli", "exp": time.Now().Add(time.Hour).Unix()}
	raw := p.signer.Token(t, "key-1", claims)
	cause := errors.New("private provider credentials must not reach output")
	for _, test := range []struct {
		name, body string
		status     int
		network    bool
	}{
		{name: "transport", network: true},
		{name: "status", status: http.StatusServiceUnavailable, body: cause.Error()},
		{name: "malformed JSON", status: http.StatusOK, body: "not JSON"},
		{name: "invalid signing key", status: http.StatusOK, body: `{"keys":[{"alg":"RS256","kty":"RSA","n":"!","e":"AQAB"}]}`},
		{name: "oversized response", status: http.StatusOK, body: strings.Repeat(" ", (256<<10)+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := *p.client
			client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Path != "/jwks" {
					return p.client.Transport.RoundTrip(request)
				}
				if test.network {
					return nil, cause
				}
				return &http.Response{StatusCode: test.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(test.body))}, nil
			})
			verifier, err := NewVerifier(VerifierConfig{Issuer: p.issuer, ClientID: "tnl-cli", HTTPClient: &client})
			if err != nil {
				t.Fatal(err)
			}
			_, err = verifier.Verify(t.Context(), raw)
			var fetch *keyFetchError
			if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrUnauthenticated) || !errors.As(err, &fetch) || test.network && !errors.Is(err, cause) {
				t.Fatalf("provider failure lost its classification or cause: %v", err)
			}
		})
	}
	verifier, err := NewVerifier(VerifierConfig{Issuer: p.issuer, ClientID: "tnl-cli", HTTPClient: p.client})
	if err != nil {
		t.Fatal(err)
	}
	wrong := oidctest.NewSigner(t).Token(t, "key-1", claims)
	if _, err := verifier.Verify(t.Context(), wrong); !errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("invalid signature = %v", err)
	}
}

func TestVerifierReusesKeysAfterDiscoveryContextEnds(t *testing.T) {
	p := newTestProvider(t, "")
	var offline atomic.Bool
	cause := errors.New("provider is offline")
	client := *p.client
	client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if offline.Load() {
			return nil, cause
		}
		return p.client.Transport.RoundTrip(request)
	})
	verifier, err := NewVerifier(VerifierConfig{Issuer: p.issuer, ClientID: "tnl-cli", HTTPClient: &client})
	if err != nil {
		t.Fatal(err)
	}
	raw := p.signer.Token(t, "key-1", map[string]any{"iss": p.issuer, "sub": "subject", "aud": "tnl-cli", "exp": time.Now().Add(time.Hour).Unix()})
	ctx, cancel := context.WithCancel(t.Context())
	if _, err := verifier.Verify(ctx, raw); err != nil {
		t.Fatal(err)
	}
	cancel()
	offline.Store(true)
	if _, err := verifier.Verify(t.Context(), raw); err != nil {
		t.Fatalf("cached verification depends on ended discovery request: %v", err)
	}
}
