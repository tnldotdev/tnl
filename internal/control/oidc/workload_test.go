package oidcauth_test

import (
	"errors"
	"testing"
	"time"

	oidcauth "github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
)

func TestWorkloadProviderSignedIdentity(t *testing.T) {
	for _, provider := range []string{"vercel-team", "vercel-global", "fly", "oidc"} {
		t.Run(provider, func(t *testing.T) {
			now := time.Now()
			p := oidcauth.WorkloadTrust{Provider: "vercel", Issuer: "https://oidc.vercel.com/acme", Audience: "https://vercel.com/acme", Claims: map[string]string{"owner": "acme", "owner_id": "team_one", "project_id": "prj_store", "environment": "production"}}
			claims := map[string]any{"iss": p.Issuer, "aud": p.Audience, "sub": "owner:acme:project:storefront:environment:production", "owner": "acme", "owner_id": "team_one", "project": "storefront", "project_id": "prj_store", "environment": "production", "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(2 * time.Hour).Unix()}
			if provider == "vercel-global" {
				p.Issuer = "https://oidc.vercel.com"
				claims["iss"] = p.Issuer
			}
			if provider == "fly" {
				p = oidcauth.WorkloadTrust{Provider: "fly", Issuer: "https://oidc.fly.io/acme", Audience: "https://fly.io/acme", Claims: map[string]string{"org_name": "acme", "org_id": "123", "app_name": "store", "app_id": "456", "machine_id": "148e21ea7e46e8"}}
				claims = map[string]any{"iss": p.Issuer, "aud": p.Audience, "sub": "acme:store:store-one", "org_name": "acme", "org_id": "123", "app_name": "store", "app_id": "456", "machine_id": "148e21ea7e46e8", "machine_name": "store-one", "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix()}
			}
			if provider == "oidc" {
				p = oidcauth.WorkloadTrust{Provider: "oidc", Issuer: "https://issuer.example/workloads", Audience: "tnl-store", Claims: map[string]string{"sub": "service:store", "tenant": "acme"}}
				claims = map[string]any{"iss": p.Issuer, "aud": p.Audience, "sub": "service:store", "tenant": "acme", "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Hour).Unix()}
			}
			p.JWKSURL = p.Issuer + "/.well-known/jwks"
			issuer := githubtest.NewProvider(t, p.Issuer)
			v, err := oidcauth.NewWorkloadVerifier("https://control.example", issuer.Client)
			if err != nil {
				t.Fatal(err)
			}
			raw := issuer.Sign(t, claims)
			verified, err := v.Verify(t.Context(), p, raw)
			if err != nil || verified.Provider != p.Provider || !verified.Matches(p) {
				t.Fatal("signed provider rejected", err)
			}
			// provider tokens may be reused; session replay is a separate key-bound boundary.
			if _, err = v.Verify(t.Context(), p, raw); err != nil {
				t.Fatal("provider token was consumed", err)
			}
			for _, field := range []string{"iss", "aud", "sub", "iat", "nbf", "exp"} {
				t.Run(field, func(t *testing.T) {
					original := claims[field]
					defer func() { claims[field] = original }()
					claims[field] = "wrong"
					if field == "iat" || field == "nbf" {
						claims[field] = now.Add(time.Hour).Unix()
					}
					if field == "exp" {
						claims[field] = now.Add(-time.Second).Unix()
					}
					if _, err := v.Verify(t.Context(), p, issuer.Sign(t, claims)); !errors.Is(err, oidcauth.ErrUnauthenticated) {
						t.Fatal("invalid signed claim accepted", err)
					}
				})
			}
			for field := range p.Claims {
				if field == "sub" {
					continue
				}
				original := claims[field]
				claims[field] = "other"
				if _, err = v.Verify(t.Context(), p, issuer.Sign(t, claims)); !errors.Is(err, oidcauth.ErrUnauthenticated) {
					t.Fatalf("wrong %s accepted: %v", field, err)
				}
				claims[field] = original
			}
			other := p
			other.Provider = "github"
			if _, err = v.Verify(t.Context(), other, raw); err == nil {
				t.Fatal("provider chain accepted another issuer")
			}
			foreign := githubtest.NewProvider(t, p.Issuer)
			if _, err = v.Verify(t.Context(), p, foreign.Sign(t, claims)); !errors.Is(err, oidcauth.ErrUnauthenticated) {
				t.Fatal("wrong signing key accepted", err)
			}
		})
	}
}
