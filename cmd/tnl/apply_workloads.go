package main

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/githubmetadata"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var readGitHubRepository = githubmetadata.Resolve

// only trusted apply binds immutable IDs. ordinary app preparation and jobs
// never consult gh, and unchanged applies reuse the saved binding.
func bindProjectWorkloads(ctx context.Context, project projectConfiguration, declaration *controlv1.ProjectConfiguration, saved controlv1.ProjectConfiguration) error {
	if len(project.Config.Workloads) == 0 {
		return nil
	}
	bindings := map[string]controlstate.ProjectWorkloadGitHub{}
	data, err := json.Marshal(saved)
	if err != nil {
		return err
	}
	var previous controlstate.ProjectConfiguration
	if err = json.Unmarshal(data, &previous); err != nil {
		return err
	}
	for _, p := range previous.Workloads {
		if p.Provider == "github" && p.GitHub != nil {
			bindings[p.GitHub.Repository] = *p.GitHub
		}
	}
	policies := map[string]controlstate.ProjectWorkload{}
	for name, p := range project.Config.Workloads {
		if p.Provider != "github" {
			trust, err := bindProviderWorkload(ctx, p, previous.Workloads[name])
			if err != nil {
				return failure.Wrap("bind workload provider", failure.ProjectConfigInvalid, err)
			}
			policies[name] = controlstate.ProjectWorkload{Provider: p.Provider, Trust: trust, Services: slices.Clone(p.Services), MaxDurationSeconds: int(p.DurationLimit() / time.Second)}
			continue
		}
		repository := ""
		if p.GitHub.Repository != nil {
			repository = *p.GitHub.Repository
		} else {
			repository, err = project.GitHubRepository(ctx)
			if err != nil {
				return failure.Wrap("infer workload repository", failure.ProjectConfigInvalid, err)
			}
		}
		binding, found := bindings[repository]
		if !found {
			metadata, err := readGitHubRepository(ctx, repository)
			if err != nil {
				return failure.Wrap("bind workload repository", failure.WorkloadRepositoryMetadataUnavailable, err)
			}
			if metadata.Repository != repository {
				return failure.Wrap("bind workload repository", failure.ProjectConfigInvalid, errors.New("GitHub repository was renamed; update the origin or explicit workload repository before applying"))
			}
			binding = controlstate.ProjectWorkloadGitHub{Repository: repository, RepositoryID: metadata.RepositoryID, RepositoryOwnerID: metadata.OwnerID}
			bindings[repository] = binding
		}
		binding.WorkflowRef = repository + "/" + p.GitHub.Workflow + "@" + p.GitHub.Ref
		binding.Ref = p.GitHub.Ref
		binding.Events = slices.Clone(p.GitHub.Events)
		binding.Environment = ""
		if p.GitHub.Environment != nil {
			binding.Environment = *p.GitHub.Environment
		}
		binding.JobWorkflowRef = ""
		if p.GitHub.ReusableWorkflow != nil {
			binding.JobWorkflowRef = *p.GitHub.ReusableWorkflow
		}
		duration := time.Hour
		if p.MaxDuration != nil {
			duration = p.MaxDuration.Value()
		}
		policies[name] = controlstate.ProjectWorkload{Provider: "github", GitHub: &binding, Services: slices.Clone(p.Services), MaxDurationSeconds: int(duration / time.Second)}
	}
	data, err = json.Marshal(policies)
	if err != nil {
		return err
	}
	var wire map[string]controlv1.ProjectWorkload
	if err = json.Unmarshal(data, &wire); err != nil {
		return err
	}
	declaration.Workloads = &wire
	return nil
}
