package oidcauth_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	oidcauth "github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
)

func TestWorkloadJWKSigningAlgorithms(t *testing.T) {
	for _, alg := range []jose.SignatureAlgorithm{jose.ES256, jose.EdDSA, jose.ES384} {
		t.Run(string(alg), func(t *testing.T) {
			var private, public any
			if alg == jose.EdDSA {
				pub, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				private, public = key, pub
			} else {
				curve := elliptic.P256()
				if alg == jose.ES384 {
					curve = elliptic.P384()
				}
				key, err := ecdsa.GenerateKey(curve, rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				private, public = key, &key.PublicKey
			}
			keys := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: public, KeyID: "workload", Algorithm: string(alg), Use: "sig"}}})
			}))
			defer keys.Close()
			p := oidcauth.WorkloadTrust{Provider: "oidc", Issuer: keys.URL, JWKSURL: keys.URL + "/.well-known/jwks", Audience: "tnl-store", Claims: map[string]string{"sub": "service:store"}}
			v, err := oidcauth.NewWorkloadVerifier("https://control.example", keys.Client())
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			sign := func(claims map[string]any) string {
				t.Helper()
				signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: private}, (&jose.SignerOptions{}).WithHeader("kid", "workload"))
				if err != nil {
					t.Fatal(err)
				}
				data, err := json.Marshal(claims)
				if err != nil {
					t.Fatal(err)
				}
				signed, err := signer.Sign(data)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := signed.CompactSerialize()
				if err != nil {
					t.Fatal(err)
				}
				return raw
			}
			raw := sign(map[string]any{"iss": p.Issuer, "aud": p.Audience, "sub": "service:store", "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Minute).Unix()})
			verified, err := v.Verify(t.Context(), p, raw)
			if alg == jose.ES384 {
				if !errors.Is(err, oidcauth.ErrUnauthenticated) {
					t.Fatal("unsupported signing algorithm accepted", err)
				}
			} else if err != nil || !verified.Matches(p) {
				t.Fatal("supported JWK alg rejected", err)
			}
			// the generic key-fetch configuration must not widen GitHub or the
			// RS256-only provider profiles, even with a valid signed assertion.
			github := sign(githubtest.Claims("https://control.example", now))
			if _, err := v.Verify(t.Context(), oidcauth.WorkloadTrust{Provider: "github"}, github); !errors.Is(err, oidcauth.ErrUnauthenticated) {
				t.Fatal("GitHub accepted a non-RS256 assertion", err)
			}
			for _, provider := range []string{"vercel", "fly"} {
				p.Provider = provider
				if _, err := v.Verify(t.Context(), p, raw); !errors.Is(err, oidcauth.ErrUnauthenticated) {
					t.Fatal("provider accepted a non-RS256 assertion", err)
				}
			}
		})
	}
}
