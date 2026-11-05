package config

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
)

type WorkloadGitLab struct {
	Project        string  `json:"project,omitempty" yaml:"project,omitempty" jsonschema_description:"GitLab project path; defaults to the Git origin on the selected server."`
	Server         string  `json:"server,omitempty" yaml:"server,omitempty" jsonschema_description:"GitLab HTTPS origin; defaults to https://gitlab.com."`
	Branch         *string `json:"branch,omitempty" yaml:"branch,omitempty" jsonschema_description:"Exact branch; defaults to the saved project default branch. Mutually exclusive with tag."`
	Tag            *string `json:"tag,omitempty" yaml:"tag,omitempty"`
	PipelineSource string  `json:"pipeline_source,omitempty" yaml:"pipeline_source,omitempty" jsonschema_description:"Exact GitLab pipeline source; defaults to push."`
	Environment    string  `json:"environment,omitempty" yaml:"environment,omitempty"`
	Audience       string  `json:"audience,omitempty" yaml:"audience,omitempty" jsonschema_description:"Intended token recipient; defaults to the control URL."`
}

const GitLabTokenEnv = "TNL_ID_TOKEN"

var gitLabPathSegment = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)

func ValidGitLabProject(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) < 2 || len(value) > 512 {
		return false
	}
	for _, part := range parts {
		if !gitLabPathSegment.MatchString(part) || strings.HasSuffix(part, ".") || strings.HasSuffix(part, ".git") {
			return false
		}
	}
	return true
}

func ValidGitLabServer(value string) bool {
	u, err := url.Parse(value)
	return err == nil && WorkloadHTTPS(value) && u.Path == "" && u.Host == strings.ToLower(u.Host) && !strings.ContainsAny(u.Host, "*?[]")
}

var GitLabPipelineSources = []string{"push", "web", "schedule", "api", "trigger", "pipeline", "parent_pipeline", "merge_request_event", "external", "external_pull_request_event", "chat", "webide", "ondemand_dast_scan", "ondemand_dast_validation", "security_orchestration_policy"}

func ValidGitLabPipelineSource(value string) bool {
	return slices.Contains(GitLabPipelineSources, value)
}

func (g WorkloadGitLab) Origin() string {
	if g.Server != "" {
		return g.Server
	}
	return "https://gitlab.com"
}

func (g WorkloadGitLab) Source() string {
	if g.PipelineSource != "" {
		return g.PipelineSource
	}
	return "push"
}

func (g WorkloadGitLab) ExecutionRef(defaultBranch string) string {
	if g.Tag != nil {
		return "refs/tags/" + *g.Tag
	}
	if g.Branch != nil {
		return "refs/heads/" + *g.Branch
	}
	if defaultBranch != "" {
		return "refs/heads/" + defaultBranch
	}
	return ""
}

func (g WorkloadGitLab) valid() bool {
	return ValidGitLabServer(g.Origin()) && (g.Project == "" || ValidGitLabProject(g.Project)) && !(g.Branch != nil && g.Tag != nil) && (g.Branch == nil || ValidWorkloadRef("refs/heads/"+*g.Branch)) && (g.Tag == nil || ValidWorkloadRef("refs/tags/"+*g.Tag)) && ValidGitLabPipelineSource(g.Source()) && (g.Environment == "" || ExactWorkloadValue(g.Environment)) && (g.Audience == "" || ExactWorkloadValue(g.Audience))
}
