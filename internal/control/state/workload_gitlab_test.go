package state

import (
	"errors"
	"maps"
	"testing"

	"github.com/tnldotdev/tnl/internal/control/oidc"
)

func TestGitLabWorkloadTrustPinsProjectAndInstance(t *testing.T) {
	p := ProjectWorkload{Provider: "gitlab", GitLab: &ProjectWorkloadGitLab{Server: "https://gitlab.example", Project: "shop/storefront", ProjectId: "123", NamespaceId: "456", DefaultBranch: new("trunk")}, Trust: oidc.WorkloadTrust{Provider: "gitlab", Issuer: "https://gitlab.example", JWKSURL: "https://gitlab.example/oauth/discovery/keys", Audience: "https://control.example", Claims: map[string]string{"job_project_id": "123", "job_namespace_id": "456", "job_project_path": "shop/storefront", "job_namespace_path": "shop", "ref_path": "refs/heads/trunk", "pipeline_source": "push"}}}
	if err := p.validateTrust(); err != nil {
		t.Fatal("valid GitLab trust rejected", err)
	}
	for _, change := range []func(*ProjectWorkload){
		func(p *ProjectWorkload) { p.GitLab = nil },
		func(p *ProjectWorkload) { p.Trust.Issuer = "https://another.example" },
		func(p *ProjectWorkload) { p.Trust.JWKSURL = "https://another.example/keys" },
		func(p *ProjectWorkload) { p.Trust.Claims["job_project_id"] = "999" },
		func(p *ProjectWorkload) { delete(p.Trust.Claims, "job_namespace_id") },
		func(p *ProjectWorkload) { p.Trust.Claims["job_project_path"] = "shop/another" },
		func(p *ProjectWorkload) { p.Trust.Claims["ref_path"] = "*" },
		func(p *ProjectWorkload) { p.Trust.Claims["pipeline_source"] = "*" },
		func(p *ProjectWorkload) { p.Trust.Claims["user_login"] = "mutable-user" },
	} {
		bad := p
		bad.Trust.Claims = maps.Clone(p.Trust.Claims)
		change(&bad)
		if err := bad.validateTrust(); !errors.Is(err, ErrProjectConfigurationInvalid) {
			t.Fatal("changed GitLab authority accepted", err)
		}
	}
}
