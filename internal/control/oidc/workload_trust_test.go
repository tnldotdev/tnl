package oidc_test

import (
	"errors"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
)

func machineProviderTrusts() []oidc.WorkloadTrust {
	return []oidc.WorkloadTrust{
		{Provider: "github", Issuer: oidc.GitHubIssuer, JWKSURL: oidc.GitHubIssuer + "/.well-known/jwks", Audience: "https://control.example", Claims: map[string]string{"repository": "example/repository", "repository_id": "12345", "repository_owner_id": "6789", "workflow_ref": "example/repository/.github/workflows/test.yml@refs/heads/main", "ref": "refs/heads/main"}, Events: []string{"push", "workflow_dispatch"}},
		{Provider: "vercel", Issuer: "https://oidc.vercel.com/acme", JWKSURL: "https://oidc.vercel.com/acme/.well-known/jwks", Audience: "https://vercel.com/acme", Claims: map[string]string{"owner": "acme", "owner_id": "team_one", "project_id": "prj_store", "environment": "production"}},
		{Provider: "fly", Issuer: "https://oidc.fly.io/acme", JWKSURL: "https://oidc.fly.io/acme/.well-known/jwks", Audience: "https://control.example", Claims: map[string]string{"org_name": "acme", "org_id": "123", "app_name": "store", "app_id": "456"}},
		{Provider: "google", Issuer: config.GoogleWorkloadIssuer, JWKSURL: config.GoogleWorkloadJWKS, Audience: "https://control.example", Claims: map[string]string{"sub": "112010400000000710080"}},
		{Provider: "kubernetes", Issuer: "https://oidc.eks.us-west-2.amazonaws.com/id/example", JWKSURL: "https://oidc.eks.us-west-2.amazonaws.com/id/example/keys", Audience: "https://control.example", Claims: map[string]string{"sub": "system:serviceaccount:production:orders", "service_account_uid": "11111111-1111-4111-8111-111111111111"}},
		{Provider: "gitlab", Issuer: "https://gitlab.example", JWKSURL: "https://gitlab.example/oauth/discovery/keys", Audience: "https://control.example", Claims: map[string]string{"job_project_id": "123", "job_namespace_id": "456", "job_project_path": "shop/storefront", "job_namespace_path": "shop", "ref_path": "refs/heads/trunk", "pipeline_source": "push"}},
		{Provider: "oidc", Issuer: "https://issuer.example", JWKSURL: "https://issuer.example/keys", Audience: "https://control.example", Claims: map[string]string{"sub": "service:orders"}},
	}
}

func TestWorkloadTrustProviderApproval(t *testing.T) {
	for _, trust := range machineProviderTrusts() {
		t.Run(trust.Provider, func(t *testing.T) {
			if err := trust.Validate(); err != nil {
				t.Fatal("valid manager policy rejected", err)
			}
			for _, test := range []struct {
				name string
				edit func(*oidc.WorkloadTrust)
			}{
				{"missing audience", func(p *oidc.WorkloadTrust) { p.Audience = "" }},
				{"wildcard audience", func(p *oidc.WorkloadTrust) { p.Audience = "*" }},
				{"invalid issuer", func(p *oidc.WorkloadTrust) { p.Issuer = "http://issuer.example" }},
				{"invalid keys", func(p *oidc.WorkloadTrust) { p.JWKSURL = "https://issuer.example/keys?selected=token" }},
				{"reserved claim", func(p *oidc.WorkloadTrust) { p.Claims["aud"] = "another" }},
				{"unapproved provider", func(p *oidc.WorkloadTrust) { p.Provider = "another" }},
				{"wildcard claim", func(p *oidc.WorkloadTrust) { p.Claims["sub"] = "*" }},
				{"missing stable identity", func(p *oidc.WorkloadTrust) { p.Claims = nil }},
				{"unexpected events", func(p *oidc.WorkloadTrust) {
					p.Events = []string{}
				}},
			} {
				t.Run(test.name, func(t *testing.T) {
					p := trust
					p.Claims, p.Events = maps.Clone(trust.Claims), slices.Clone(trust.Events)
					test.edit(&p)
					if err := p.Validate(); !errors.Is(err, oidc.ErrUnauthenticated) {
						t.Fatal("invalid manager policy accepted", err)
					}
				})
			}
			for name := range trust.Claims {
				p := trust
				p.Claims = maps.Clone(trust.Claims)
				delete(p.Claims, name)
				if err := p.Validate(); err == nil {
					t.Fatal("missing required stable claim accepted", name)
				}
			}
			if trust.Provider != "oidc" && trust.Provider != "kubernetes" {
				p := trust
				p.Issuer = "https://foreign.example"
				if p.Validate() == nil {
					t.Fatal("provider accepted a foreign issuer")
				}
				p = trust
				p.JWKSURL = "https://foreign.example/keys"
				if p.Validate() == nil {
					t.Fatal("provider accepted a foreign key endpoint")
				}
			}
		})
	}
}

func TestGitHubWorkloadTrustServingExecution(t *testing.T) {
	p := machineProviderTrusts()[0]
	issuer := githubtest.NewKeySet(t, p.JWKSURL)
	v, err := oidc.NewWorkloadVerifier(p.Audience, issuer.Client)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := githubtest.Claims(p.Audience, now)
	first, err := v.Verify(t.Context(), p, issuer.Sign(t, claims))
	if err != nil || first.GitHub == nil || !first.Matches(p) || first.Audience != p.Audience || first.TrustDigest != p.Digest() {
		t.Fatal("verified execution lost approved trust", err)
	}
	claims["jti"], claims["exp"] = "rotated", now.Add(6*time.Minute).Unix()
	rotated, err := v.Verify(t.Context(), p, issuer.Sign(t, claims))
	if err != nil || first.IdentityDigest() != rotated.IdentityDigest() {
		t.Fatal("same job rotation changed owner", err)
	}
	for _, field := range []string{"run_id", "run_attempt", "check_run_id"} {
		original := claims[field]
		claims[field] = "999"
		other, err := v.Verify(t.Context(), p, issuer.Sign(t, claims))
		if err != nil || first.IdentityDigest() == other.IdentityDigest() {
			t.Fatal("different job inherited execution identity", field, err)
		}
		claims[field] = original
	}
	claims["event_name"] = "workflow_dispatch"
	if _, err := v.Verify(t.Context(), p, issuer.Sign(t, claims)); err != nil {
		t.Fatal("second approved event rejected", err)
	}
	claims["event_name"] = "pull_request"
	if _, err := v.Verify(t.Context(), p, issuer.Sign(t, claims)); !errors.Is(err, oidc.ErrUnauthenticated) {
		t.Fatal("unapproved event accepted", err)
	}
	claims["event_name"] = "push"
	for field := range p.Claims {
		original := claims[field]
		claims[field] = "another"
		if _, err := v.Verify(t.Context(), p, issuer.Sign(t, claims)); !errors.Is(err, oidc.ErrUnauthenticated) {
			t.Fatal("wrong pinned GitHub claim accepted", field, err)
		}
		claims[field] = original
	}
	otherAudience := p
	otherAudience.Audience = "https://foreign.example"
	if _, err := v.Verify(t.Context(), otherAudience, issuer.Sign(t, claims)); !errors.Is(err, oidc.ErrUnauthenticated) {
		t.Fatal("GitHub trust changed fixed control audience", err)
	}
}
