package workloadsetup

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var ErrGitLabAuthentication = errors.New("workload setup needs existing glab authentication with read access to the selected GitLab project")

func (r resolver) gitlab(ctx context.Context, o Options, g *config.WorkloadGitLab, previous controlv1.ProjectWorkload) (controlv1.WorkloadTrust, *controlv1.ProjectWorkloadGitLab, error) {
	t := controlv1.WorkloadTrust{Provider: controlv1.WorkloadGitLab, Issuer: g.Origin(), JwksUrl: g.Origin() + "/oauth/discovery/keys", Audience: o.Server, Claims: map[string]string{}}
	if g.Audience != "" {
		t.Audience = g.Audience
	}
	project := g.Project
	if project == "" {
		output, err := r.run(ctx, o.Directory, "git", "remote", "get-url", "origin")
		if err != nil {
			return t, nil, errors.Join(ErrBinding, err)
		}
		project = gitLabOriginProject(strings.TrimSpace(string(output)), g.Origin())
	}
	if !config.ValidGitLabProject(project) {
		return t, nil, ErrBinding
	}
	var binding controlv1.ProjectWorkloadGitLab
	if previous.Provider == t.Provider && previous.Gitlab != nil && previous.Gitlab.Server == g.Origin() && previous.Gitlab.Project == project {
		binding = *previous.Gitlab
	} else {
		server, _ := url.Parse(g.Origin())
		output, err := r.run(ctx, o.Directory, "glab", "api", "--hostname", server.Host, "projects/"+url.PathEscape(project))
		if err != nil {
			return t, nil, errors.Join(ErrGitLabAuthentication, err)
		}
		var metadata struct {
			ID            json.Number `json:"id"`
			Path          string      `json:"path_with_namespace"`
			DefaultBranch string      `json:"default_branch"`
			Archived      bool        `json:"archived"`
			Namespace     struct {
				ID   json.Number `json:"id"`
				Path string      `json:"full_path"`
			} `json:"namespace"`
		}
		if json.Unmarshal(output, &metadata) != nil || metadata.Archived || metadata.Path != project || !config.ValidWorkloadNumericID(metadata.ID.String()) || !config.ValidWorkloadNumericID(metadata.Namespace.ID.String()) || metadata.Namespace.Path != project[:strings.LastIndex(project, "/")] || metadata.DefaultBranch != "" && !config.ValidWorkloadRef("refs/heads/"+metadata.DefaultBranch) {
			return t, nil, ErrBinding
		}
		binding = controlv1.ProjectWorkloadGitLab{Server: g.Origin(), Project: project, ProjectId: metadata.ID.String(), NamespaceId: metadata.Namespace.ID.String()}
		if metadata.DefaultBranch != "" {
			binding.DefaultBranch = &metadata.DefaultBranch
		}
	}
	if previous.Provider == t.Provider && (previous.Gitlab == nil || previous.Gitlab.Server != binding.Server || previous.Gitlab.ProjectId != binding.ProjectId || previous.Gitlab.NamespaceId != binding.NamespaceId) {
		return t, nil, ErrRebinding
	}
	defaultBranch := ""
	if binding.DefaultBranch != nil {
		defaultBranch = *binding.DefaultBranch
	}
	ref := g.ExecutionRef(defaultBranch)
	if !config.ValidWorkloadRef(ref) {
		return t, nil, ErrBinding
	}
	t.Claims = map[string]string{"job_project_id": binding.ProjectId, "job_namespace_id": binding.NamespaceId, "job_project_path": binding.Project, "job_namespace_path": binding.Project[:strings.LastIndex(binding.Project, "/")], "ref_path": ref, "pipeline_source": g.Source()}
	if g.Environment != "" {
		t.Claims["environment"] = g.Environment
	}
	return t, &binding, nil
}

func gitLabOriginProject(remote, origin string) string {
	server, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	if path, ok := strings.CutPrefix(remote, "git@"+server.Host+":"); ok {
		return strings.TrimSuffix(path, ".git")
	}
	u, err := url.Parse(remote)
	if err != nil || u.Host != server.Host || u.Scheme != "https" && u.Scheme != "ssh" || u.RawQuery != "" || u.Fragment != "" || u.User != nil && (u.Scheme != "ssh" || u.User.Username() != "git" || u.User.String() != "git") {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(u.Path, "/"), ".git")
}
