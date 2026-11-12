package oidc

import (
	"slices"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming"
)

// validate checks manager-saved provider policy before registration or key fetch.
// provider-specific executions and matching remain owned by the serving verifier.
func (p WorkloadTrust) Validate() error {
	if !config.WorkloadHTTPS(p.Issuer) || len(p.Issuer) > 2048 || !config.WorkloadHTTPS(p.JWKSURL) || len(p.JWKSURL) > 2048 || !config.ExactWorkloadValue(p.Audience) || len(p.Claims) == 0 || len(p.Claims) > 32 || p.Provider != "github" && p.Events != nil {
		return ErrUnauthenticated
	}
	for key, value := range p.Claims {
		if !config.ExactWorkloadValue(key) || !config.ExactWorkloadValue(value) || slices.Contains([]string{"iss", "aud", "iat", "nbf", "exp"}, key) {
			return ErrUnauthenticated
		}
	}
	require := func(keys ...string) bool {
		for _, key := range keys {
			if p.Claims[key] == "" {
				return false
			}
		}
		return true
	}
	allow := func(keys ...string) bool {
		for key := range p.Claims {
			if !slices.Contains(keys, key) {
				return false
			}
		}
		return true
	}
	switch p.Provider {
	case "github":
		if p.Issuer != GitHubIssuer || p.JWKSURL != githubJWKS || !require("repository", "repository_id", "repository_owner_id", "workflow_ref", "ref") || !allow("sub", "repository", "repository_id", "repository_owner_id", "workflow_ref", "ref", "environment", "job_workflow_ref") || !githubNumericID.MatchString(p.Claims["repository_id"]) || !githubNumericID.MatchString(p.Claims["repository_owner_id"]) || !p.validGitHubPolicy() {
			return ErrUnauthenticated
		}
	case "gitlab":
		project := p.Claims["job_project_path"]
		if !config.ValidGitLabServer(p.Issuer) || p.JWKSURL != p.Issuer+"/oauth/discovery/keys" || !require("job_project_id", "job_namespace_id", "job_project_path", "job_namespace_path", "ref_path", "pipeline_source") || !allow("sub", "job_project_id", "job_namespace_id", "job_project_path", "job_namespace_path", "ref_path", "pipeline_source", "environment") || !config.ValidWorkloadNumericID(p.Claims["job_project_id"]) || !config.ValidWorkloadNumericID(p.Claims["job_namespace_id"]) || !config.ValidGitLabProject(project) || p.Claims["job_namespace_path"] != project[:strings.LastIndex(project, "/")] || !config.ValidWorkloadRef(p.Claims["ref_path"]) || !config.ValidGitLabPipelineSource(p.Claims["pipeline_source"]) {
			return ErrUnauthenticated
		}
	case "kubernetes":
		parts := strings.Split(p.Claims["sub"], ":")
		if len(p.Claims) != 2 || len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" || !naming.ValidAuthorityLabel(parts[2]) || !config.ValidKubernetesName(parts[3]) || !config.ValidKubernetesUID(p.Claims["service_account_uid"]) {
			return ErrUnauthenticated
		}
	case "google":
		if p.Issuer != config.GoogleWorkloadIssuer || p.JWKSURL != config.GoogleWorkloadJWKS || len(p.Claims) != 1 || !config.ValidWorkloadNumericID(p.Claims["sub"]) {
			return ErrUnauthenticated
		}
	case "vercel":
		owner := p.Claims["owner"]
		if !naming.ValidAuthorityLabel(owner) || !require("owner", "owner_id", "project_id", "environment") || !allow("sub", "owner", "owner_id", "project", "project_id", "environment") || !strings.HasPrefix(p.Claims["owner_id"], "team_") || !strings.HasPrefix(p.Claims["project_id"], "prj_") || !slices.Contains([]string{"production", "preview", "development"}, p.Claims["environment"]) || p.Issuer != "https://oidc.vercel.com" && p.Issuer != "https://oidc.vercel.com/"+owner || p.JWKSURL != p.Issuer+"/.well-known/jwks" || p.Audience != "https://vercel.com/"+owner {
			return ErrUnauthenticated
		}
	case "fly":
		if !require("org_name", "org_id", "app_name", "app_id") || !allow("sub", "org_name", "org_id", "app_name", "app_id", "machine_id") || !naming.ValidAuthorityLabel(p.Claims["org_name"]) || !naming.ValidAuthorityLabel(p.Claims["app_name"]) || p.Issuer != "https://oidc.fly.io/"+p.Claims["org_name"] || p.JWKSURL != p.Issuer+"/.well-known/jwks" {
			return ErrUnauthenticated
		}
	case "oidc":
		if !require("sub") {
			return ErrUnauthenticated
		}
	default:
		return ErrUnauthenticated
	}
	return nil
}

func (p WorkloadTrust) validGitHubPolicy() bool {
	repository, ref := p.Claims["repository"], p.Claims["ref"]
	workflow, suffix, ok := strings.Cut(strings.TrimPrefix(p.Claims["workflow_ref"], repository+"/"), "@")
	if !ok || !strings.HasPrefix(p.Claims["workflow_ref"], repository+"/") || suffix != ref || !config.ValidWorkloadRef(ref) || len(p.Events) == 0 {
		return false
	}
	g := &config.WorkloadGitHub{Repository: &repository, Workflow: workflow, Events: p.Events}
	if branch, ok := strings.CutPrefix(ref, "refs/heads/"); ok {
		g.Branch = &branch
	} else {
		g.Tag = new(strings.TrimPrefix(ref, "refs/tags/"))
	}
	if value := p.Claims["environment"]; value != "" {
		g.Environment = &value
	}
	if value := p.Claims["job_workflow_ref"]; value != "" {
		g.ReusableWorkflow = &value
	}
	return config.ValidateWorkloads(config.Services{"machine": {}}, map[string]config.Workload{"machine": {GitHub: g, Services: []string{"machine"}}}) == nil
}
