package oidc

import (
	"regexp"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
)

// GitLabExecution retains signed job provenance, not rotating JTI or timestamps.
type GitLabExecution struct {
	ProjectID        string `json:"project_id"`
	ProjectPath      string `json:"project_path"`
	NamespaceID      string `json:"namespace_id"`
	NamespacePath    string `json:"namespace_path"`
	JobProjectID     string `json:"job_project_id"`
	JobProjectPath   string `json:"job_project_path"`
	JobNamespaceID   string `json:"job_namespace_id"`
	JobNamespacePath string `json:"job_namespace_path"`
	PipelineID       string `json:"pipeline_id"`
	JobID            string `json:"job_id"`
	PipelineSource   string `json:"pipeline_source"`
	Ref              string `json:"ref"`
	RefType          string `json:"ref_type"`
	RefPath          string `json:"ref_path"`
	SHA              string `json:"sha"`
	Environment      string `json:"environment,omitempty"`
}

var gitLabCommit = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

func (g GitLabExecution) valid(subject string) bool {
	if !config.ValidGitLabProject(g.JobProjectPath) || g.ProjectID != g.JobProjectID || g.ProjectPath != g.JobProjectPath || g.NamespaceID != g.JobNamespaceID || g.NamespacePath != g.JobNamespacePath || g.JobNamespacePath != g.JobProjectPath[:strings.LastIndex(g.JobProjectPath, "/")] || !config.ValidGitLabPipelineSource(g.PipelineSource) || !gitLabCommit.MatchString(g.SHA) || g.Environment != "" && !config.ExactWorkloadValue(g.Environment) {
		return false
	}
	for _, id := range []string{g.JobProjectID, g.JobNamespaceID, g.PipelineID, g.JobID} {
		if !config.ValidWorkloadNumericID(id) {
			return false
		}
	}
	prefix := "refs/heads/"
	if g.RefType == "tag" {
		prefix = "refs/tags/"
	} else if g.RefType != "branch" {
		return false
	}
	if g.RefPath != prefix+g.Ref || !config.ValidWorkloadRef(g.RefPath) {
		return false
	}
	suffix := ":ref_type:" + g.RefType + ":ref:" + g.Ref
	return subject == "project_path:"+g.ProjectPath+suffix || subject == "project_id:"+g.ProjectID+suffix
}

func (g GitLabExecution) claims() map[string]string {
	return map[string]string{"job_project_id": g.JobProjectID, "job_namespace_id": g.JobNamespaceID, "job_project_path": g.JobProjectPath, "job_namespace_path": g.JobNamespacePath, "ref_path": g.RefPath, "pipeline_source": g.PipelineSource, "environment": g.Environment}
}
