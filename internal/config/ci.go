package config

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
)

// CI is an explicit workflow authorization policy, independent of visitor access.
type CI struct {
	GitHub      CIGitHub  `json:"github" yaml:"github" jsonschema:"required"`
	Services    []string  `json:"services" yaml:"services" jsonschema:"required,minItems=1,maxItems=32,uniqueItems=true"`
	MaxDuration *Duration `json:"max_duration,omitempty" yaml:"max_duration,omitempty" jsonschema_description:"Maximum GitHub-hosted run duration; defaults to 1h and must be positive and at most 6h."`
}

type CIGitHub struct {
	Repository       *string  `json:"repository,omitempty" yaml:"repository,omitempty" jsonschema_description:"Exact owner/repository; omitted means infer the GitHub origin when applying."`
	Workflow         string   `json:"workflow" yaml:"workflow" jsonschema:"required" jsonschema_description:"Exact .github/workflows/ file path."`
	Environment      *string  `json:"environment,omitempty" yaml:"environment,omitempty"`
	Ref              string   `json:"ref" yaml:"ref" jsonschema:"required" jsonschema_description:"Exact refs/heads/ or refs/tags/ reference."`
	Events           []string `json:"events" yaml:"events" jsonschema:"required,minItems=1,uniqueItems=true"`
	ReusableWorkflow *string  `json:"reusable_workflow,omitempty" yaml:"reusable_workflow,omitempty" jsonschema_description:"Exact owner/repository/.github/workflows/file@ref constraint."`
}

const (
	DefaultCIMaxDuration = time.Hour
	MaxCIMaxDuration     = 6 * time.Hour
)

// DurationLimit applies the shared default without changing the declaration.
func (policy CI) DurationLimit() time.Duration {
	if policy.MaxDuration == nil {
		return DefaultCIMaxDuration
	}
	return policy.MaxDuration.Value()
}

var githubRepository = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

var CIEvents = []string{"push", "pull_request", "pull_request_target", "workflow_dispatch", "workflow_call", "schedule", "release", "merge_group", "repository_dispatch", "workflow_run"}

func validateCI(configuration TNL) error {
	if len(configuration.CI) > 32 {
		return errors.New("ci may contain at most 32 policies")
	}
	for name, policy := range configuration.CI {
		if !naming.ValidServiceName(name) {
			return errors.New("ci policy name must be a lowercase DNS label")
		}
		github := policy.GitHub
		if github.Repository != nil && !githubRepository.MatchString(*github.Repository) {
			return fmt.Errorf("ci.%s.github.repository must be an exact owner/repository", name)
		}
		if !strings.HasPrefix(github.Workflow, ".github/workflows/") || validateProjectRelativeFile(github.Workflow) != nil || strings.ContainsAny(github.Workflow, "*?[]") || !(strings.HasSuffix(github.Workflow, ".yml") || strings.HasSuffix(github.Workflow, ".yaml")) || strings.Contains(strings.TrimPrefix(github.Workflow, ".github/workflows/"), "/") {
			return fmt.Errorf("ci.%s.github.workflow must be an exact .github/workflows/ file path", name)
		}
		if !(strings.HasPrefix(github.Ref, "refs/heads/") || strings.HasPrefix(github.Ref, "refs/tags/")) || strings.ContainsAny(github.Ref, "*?[]\\ \t\r\n\x00") || strings.HasSuffix(github.Ref, "/") || strings.Contains(github.Ref, "..") {
			return fmt.Errorf("ci.%s.github.ref must be an exact refs/heads/ or refs/tags/ reference", name)
		}
		if github.Environment != nil && (strings.TrimSpace(*github.Environment) == "" || strings.TrimSpace(*github.Environment) != *github.Environment || strings.ContainsAny(*github.Environment, "\r\n\x00")) {
			return fmt.Errorf("ci.%s.github.environment must be a nonempty exact name", name)
		}
		if github.ReusableWorkflow != nil {
			workflow, ref, found := strings.Cut(*github.ReusableWorkflow, "@")
			parts := strings.Split(workflow, "/")
			if !found || ref == "" || len(parts) != 5 || !githubRepository.MatchString(strings.Join(parts[:min(2, len(parts))], "/")) || parts[2] != ".github" || parts[3] != "workflows" || validateProjectRelativeFile(workflow) != nil || strings.ContainsAny(*github.ReusableWorkflow, "*?[] \t\r\n\x00") || !(strings.HasSuffix(workflow, ".yml") || strings.HasSuffix(workflow, ".yaml")) {
				return fmt.Errorf("ci.%s.github.reusable_workflow must constrain an exact reusable workflow and ref", name)
			}
		}
		if len(github.Events) == 0 || len(github.Events) > len(CIEvents) {
			return fmt.Errorf("ci.%s.github.events must declare supported GitHub event names", name)
		}
		seen := map[string]bool{}
		for _, event := range github.Events {
			if !slices.Contains(CIEvents, event) || seen[event] {
				return fmt.Errorf("ci.%s.github.events must contain distinct supported GitHub events", name)
			}
			seen[event] = true
		}
		if len(policy.Services) == 0 || len(policy.Services) > 32 {
			return fmt.Errorf("ci.%s.services must select configured services", name)
		}
		seen = map[string]bool{}
		for _, service := range policy.Services {
			if _, found := configuration.Services[service]; !found || seen[service] {
				return fmt.Errorf("ci.%s.services must select distinct configured service keys", name)
			}
			seen[service] = true
		}
		if policy.DurationLimit() <= 0 || policy.DurationLimit() > MaxCIMaxDuration {
			return fmt.Errorf("ci.%s.max_duration must be positive and at most 6h", name)
		}
	}
	return nil
}
