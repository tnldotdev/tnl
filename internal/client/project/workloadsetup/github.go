package workloadsetup

import (
	"context"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (r resolver) bindGitHub(ctx context.Context, o Options, g *config.WorkloadGitHub, previous controlv1.ProjectWorkload, repositories map[string]controlv1.ProjectWorkloadGitHub) (*controlv1.ProjectWorkloadGitHub, error) {
	repository := ""
	if g.Repository != nil {
		repository = *g.Repository
	} else if o.Repository != nil {
		var err error
		repository, err = o.Repository(ctx)
		if err != nil {
			return nil, failure.Wrap("bind workload repository", failure.WorkloadRepositoryMetadataUnavailable, err)
		}
	}
	if repository == "" {
		return nil, ErrBinding
	}
	binding, found := repositories[repository]
	defaultBranch := ""
	if binding.DefaultBranch != nil {
		defaultBranch = *binding.DefaultBranch
	}
	ref := g.ExecutionRef(defaultBranch)
	if !found || ref == "" {
		metadata, err := r.github(ctx, repository)
		if err != nil {
			return nil, failure.Wrap("bind workload repository", failure.WorkloadRepositoryMetadataUnavailable, err)
		}
		if metadata.Repository != repository {
			return nil, ErrBinding
		}
		if found && (binding.RepositoryId != metadata.RepositoryID || binding.RepositoryOwnerId != metadata.OwnerID) {
			return nil, ErrRebinding
		}
		binding = controlv1.ProjectWorkloadGitHub{Repository: repository, RepositoryId: metadata.RepositoryID, RepositoryOwnerId: metadata.OwnerID}
		if metadata.DefaultBranch != "" {
			binding.DefaultBranch = &metadata.DefaultBranch
		}
		if ref == "" {
			ref = g.ExecutionRef(metadata.DefaultBranch)
		}
		repositories[repository] = binding
	}
	if previous.Provider == controlv1.WorkloadGitHub && previous.Github != nil && (previous.Github.RepositoryId != binding.RepositoryId || previous.Github.RepositoryOwnerId != binding.RepositoryOwnerId) {
		return nil, ErrRebinding
	}
	if !config.ValidWorkloadRef(ref) {
		return nil, ErrBinding
	}
	binding.WorkflowRef, binding.Ref = repository+"/"+g.Workflow+"@"+ref, ref
	binding.Events = g.AllowedEvents()
	binding.Environment, binding.JobWorkflowRef = g.Environment, g.ReusableWorkflow
	return &binding, nil
}
