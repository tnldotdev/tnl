package oidc_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
)

func TestGitLabWorkloadPinsProjectAndJobProvenance(t *testing.T) {
	policy := oidc.WorkloadTrust{Provider: "gitlab", Issuer: "https://gitlab.example", JWKSURL: "https://gitlab.example/oauth/discovery/keys", Audience: "https://control.example", Claims: map[string]string{"job_project_id": "123", "job_namespace_id": "456", "job_project_path": "shop/storefront", "job_namespace_path": "shop", "ref_path": "refs/heads/trunk", "pipeline_source": "push"}}
	issuer := githubtest.NewKeySet(t, policy.JWKSURL)
	verifier, err := oidc.NewWorkloadVerifier(policy.Audience, issuer.Client)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := map[string]any{"iss": policy.Issuer, "aud": policy.Audience, "sub": "project_path:shop/storefront:ref_type:branch:ref:trunk", "iat": now.Unix(), "nbf": now.Add(-5 * time.Second).Unix(), "exp": now.Add(time.Hour).Unix(), "jti": "first-token", "project_id": "123", "project_path": "shop/storefront", "namespace_id": "456", "namespace_path": "shop", "job_project_id": "123", "job_project_path": "shop/storefront", "job_namespace_id": "456", "job_namespace_path": "shop", "pipeline_id": "1001", "job_id": "2001", "pipeline_source": "push", "ref": "trunk", "ref_type": "branch", "ref_path": "refs/heads/trunk", "sha": strings.Repeat("a", 40)}
	first, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, claims))
	if err != nil || first.GitLab == nil || !first.Matches(policy) {
		t.Fatal("valid GitLab job rejected", err)
	}
	claims["iat"], claims["exp"], claims["jti"] = now.Add(time.Second).Unix(), now.Add(2*time.Hour).Unix(), "rotated-token"
	rotated, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, claims))
	if err != nil || rotated.IdentityDigest() != first.IdentityDigest() {
		t.Fatal("same-job proof rotation replaced execution identity", err)
	}
	claims["job_id"] = "2002"
	other, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, claims))
	if err != nil || other.IdentityDigest() == first.IdentityDigest() {
		t.Fatal("another job reused execution identity", err)
	}
	claims["job_id"] = "2001"
	claims["pipeline_id"] = "1002"
	if changed, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, claims)); err != nil || changed.IdentityDigest() == first.IdentityDigest() {
		t.Fatal("another pipeline reused execution identity", err)
	}
	claims["pipeline_id"] = "1001"
	claims["project_id"], claims["job_project_id"] = "999", "999"
	if _, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, claims)); !errors.Is(err, oidc.ErrUnauthenticated) {
		t.Fatal("recreated project with consistent new IDs inherited the saved path's grant", err)
	}
	claims["project_id"], claims["job_project_id"] = "123", "123"
	claims["namespace_id"], claims["job_namespace_id"] = "999", "999"
	if _, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, claims)); !errors.Is(err, oidc.ErrUnauthenticated) {
		t.Fatal("recreated namespace with consistent new IDs inherited the saved grant", err)
	}
	claims["namespace_id"], claims["job_namespace_id"] = "456", "456"
	claims["ref"], claims["ref_path"], claims["sub"] = "another", "refs/heads/another", "project_path:shop/storefront:ref_type:branch:ref:another"
	if _, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, claims)); !errors.Is(err, oidc.ErrUnauthenticated) {
		t.Fatal("consistent signed ref bypassed the saved branch", err)
	}
	claims["ref"], claims["ref_path"], claims["sub"] = "trunk", "refs/heads/trunk", "project_path:shop/storefront:ref_type:branch:ref:trunk"
	for _, test := range []struct {
		name, field string
		value       any
	}{
		{"recreated project", "job_project_id", "999"},
		{"fork source", "project_id", "999"},
		{"fork source path", "project_path", "fork/storefront"},
		{"foreign namespace", "job_namespace_id", "999"},
		{"foreign path", "job_project_path", "shop/another"},
		{"wrong ref", "ref_path", "refs/heads/another"},
		{"inconsistent ref type", "ref_type", "tag"},
		{"wrong source", "pipeline_source", "web"},
		{"invalid job", "job_id", "0"},
		{"invalid pipeline", "pipeline_id", nil},
		{"invalid sha", "sha", "not-a-commit"},
		{"custom subject", "sub", "unrelated-custom-subject"},
		{"wrong audience", "aud", "https://another.example"},
		{"missing job project claims", "job_project_id", nil},
		{"missing not-before", "nbf", nil},
		{"expired proof", "exp", now.Add(-time.Minute).Unix()},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, err := json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			var invalid map[string]any
			if err := json.Unmarshal(data, &invalid); err != nil {
				t.Fatal(err)
			}
			invalid[test.field] = test.value
			if _, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, invalid)); !errors.Is(err, oidc.ErrUnauthenticated) {
				t.Fatal("invalid job provenance accepted", err)
			}
		})
	}
	claims["sub"] = "project_id:123:ref_type:branch:ref:trunk"
	if _, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, claims)); err != nil {
		t.Fatal("standard ID-based subject rejected", err)
	}
	policy.Claims["environment"] = "production"
	if _, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, claims)); !errors.Is(err, oidc.ErrUnauthenticated) {
		t.Fatal("missing environment bypassed selector", err)
	}
	claims["environment"] = "production"
	if _, err := verifier.Verify(t.Context(), policy, issuer.Sign(t, claims)); err != nil {
		t.Fatal("approved environment rejected", err)
	}
}
