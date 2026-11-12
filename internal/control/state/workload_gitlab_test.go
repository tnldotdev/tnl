package state

import (
	"errors"
	"maps"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/oidc"
)

func TestGitLabWorkloadTrustPinsProjectAndInstance(t *testing.T) {
	p := oidc.WorkloadTrust{Provider: "gitlab", Issuer: "https://gitlab.example", JWKSURL: "https://gitlab.example/oauth/discovery/keys", Audience: "https://control.example", Claims: map[string]string{"job_project_id": "123", "job_namespace_id": "456", "job_project_path": "shop/storefront", "job_namespace_path": "shop", "ref_path": "refs/heads/trunk", "pipeline_source": "push"}}
	if err := validateMachineOIDCTrust(p); err != nil {
		t.Fatal("valid GitLab trust rejected", err)
	}
	for _, change := range []func(*oidc.WorkloadTrust){
		func(p *oidc.WorkloadTrust) { p.Issuer = "https://another.example" },
		func(p *oidc.WorkloadTrust) { p.JWKSURL = "https://another.example/keys" },
		func(p *oidc.WorkloadTrust) { delete(p.Claims, "job_namespace_id") },
		func(p *oidc.WorkloadTrust) { p.Claims["ref_path"] = "*" },
		func(p *oidc.WorkloadTrust) { p.Claims["pipeline_source"] = "*" },
		func(p *oidc.WorkloadTrust) { p.Claims["user_login"] = "mutable-user" },
	} {
		bad := p
		bad.Claims = maps.Clone(p.Claims)
		change(&bad)
		if err := validateMachineOIDCTrust(bad); !errors.Is(err, ErrEnvironmentInvalid) {
			t.Fatal("changed GitLab authority accepted", err)
		}
	}
	// another exact project is a valid policy, but cannot match the originally
	// approved job. state must use verifier-owned matching, not setup selectors.
	for _, field := range []string{"job_project_id", "job_project_path"} {
		bad := p
		bad.Claims = maps.Clone(p.Claims)
		bad.Claims[field] = "999"
		if field == "job_project_path" {
			bad.Claims[field] = "shop/another"
		}
		execution := oidc.WorkloadExecution{Provider: p.Provider, Issuer: p.Issuer, Audience: p.Audience, TrustDigest: bad.Digest(), Subject: "job", GitLab: &oidc.GitLabExecution{ProjectID: "123", NamespaceID: "456", ProjectPath: "shop/storefront", NamespacePath: "shop", RefPath: "refs/heads/trunk", PipelineSource: "push"}}
		if execution.Matches(bad) {
			t.Fatal("another project acquired the original job", field)
		}
	}
	if err := config.ValidateWorkloads(config.Services{"api": {}}, map[string]config.Workload{"test": {Services: []string{"api"}}}); err == nil {
		t.Fatal("missing GitLab setup accepted")
	}
}
