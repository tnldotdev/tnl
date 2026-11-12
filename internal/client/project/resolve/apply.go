package resolve

import (
	"context"
	"errors"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type EnvironmentBackend interface {
	CreateServiceDefinition(context.Context, string, controlv1.CreateServiceDefinitionRequest) (controlv1.ServiceDefinitionRevision, error)
	ListEnvironments(context.Context, string, string) ([]controlv1.Environment, error)
	CreateEnvironment(context.Context, string, controlv1.CreateEnvironmentRequest) (controlv1.Environment, error)
	ApplyEnvironment(context.Context, string, string, controlv1.ApplyEnvironmentRequest) (controlv1.Environment, error)
	ListCollections(context.Context, string, string) ([]controlv1.Collection, error)
	CreateCollection(context.Context, string, controlv1.CreateCollectionRequest) (controlv1.Collection, error)
}

// apply environment publishes immutable shape, then mutates exactly one saved
// environment. permission changes require their own authority operations.
func ApplyEnvironment(ctx context.Context, backend EnvironmentBackend, project clientproject.Project, current team.Context, name, idempotencyKey string) (controlv1.Environment, error) {
	var zero controlv1.Environment
	declared := project.Config
	if project.Declared != nil {
		declared = *project.Declared
	}
	environment, found := declared.Environments[name]
	if !found || name == "local" {
		return zero, errors.New("--environment must select a declared remote environment")
	}
	team := current.Team().Id
	var domainID *string
	if environment.Domain != nil {
		domain, err := current.ReadyDomain(*environment.Domain)
		if err != nil {
			return zero, err
		}
		domainID = &domain.Id
	}
	targets, err := EnvironmentTargets(ctx, project, name)
	if err != nil {
		return zero, err
	}
	definition, err := Definition(project)
	if err != nil {
		return zero, err
	}
	source, err := project.SourceIdentity(ctx)
	if err != nil {
		return zero, err
	}
	saved, err := backend.ListEnvironments(ctx, team, source.Key)
	if err != nil {
		return zero, err
	}
	var selected *controlv1.Environment
	for _, candidate := range saved {
		if candidate.TeamId != team || candidate.ProjectKey != source.Key {
			return zero, invalidEnvironmentResponse()
		}
		if candidate.Name == name {
			if selected != nil {
				return zero, invalidEnvironmentResponse()
			}
			selected = &candidate
		}
	}
	var collection *controlv1.Collection
	if environment.Collection != nil {
		collections, err := backend.ListCollections(ctx, team, source.Key)
		if err != nil {
			return zero, err
		}
		for _, candidate := range collections {
			if candidate.TeamId != team || candidate.ProjectKey != source.Key {
				return zero, invalidEnvironmentResponse()
			}
			if candidate.Name == *environment.Collection {
				if collection != nil {
					return zero, invalidEnvironmentResponse()
				}
				collection = &candidate
			}
		}
	}
	if selected != nil {
		if domainID != nil && *domainID != selected.DomainId {
			return zero, errors.New("an existing environment's domain cannot be changed by apply")
		}
		if environment.Collection != nil && (collection == nil || selected.CollectionId == nil || *selected.CollectionId != collection.CollectionId) {
			return zero, errors.New("an existing environment's collection membership cannot be changed by apply")
		}
	}
	revision, err := backend.CreateServiceDefinition(ctx, source.Key, controlv1.CreateServiceDefinitionRequest{TeamId: team, SourceFingerprint: source.Fingerprint, ProjectLabel: &source.Label, Definition: definition})
	if err != nil {
		return zero, err
	}
	if revision.TeamId != team || revision.ProjectKey != source.Key || revision.SourceFingerprint != source.Fingerprint || revision.Revision < 1 {
		return zero, invalidEnvironmentResponse()
	}
	var applied controlv1.Environment
	if selected == nil {
		request := controlv1.CreateEnvironmentRequest{TeamId: team, SourceFingerprint: source.Fingerprint, ProjectLabel: &source.Label, Name: name, DefinitionRevision: &revision.Revision, Targets: targets, Public: environment.Public, DomainId: domainID, IdempotencyKey: idempotencyKey}
		if environment.Collection != nil {
			if collection == nil {
				created, createErr := backend.CreateCollection(ctx, source.Key, controlv1.CreateCollectionRequest{TeamId: team, Name: *environment.Collection, DefaultDefinitionRevision: revision.Revision})
				if createErr != nil {
					return zero, createErr
				}
				if created.TeamId != team || created.ProjectKey != source.Key || created.Name != *environment.Collection || created.MutationRevision < 1 {
					return zero, invalidEnvironmentResponse()
				}
				collection = &created
			}
			request.CollectionId, request.ExpectedCollectionRevision = &collection.CollectionId, &collection.MutationRevision
		}
		applied, err = backend.CreateEnvironment(ctx, source.Key, request)
	} else {
		applied, err = backend.ApplyEnvironment(ctx, source.Key, selected.Id, controlv1.ApplyEnvironmentRequest{TeamId: team, ExpectedRevision: selected.MutationRevision, DefinitionRevision: revision.Revision, Targets: &targets, Public: environment.Public})
	}
	if err != nil {
		return zero, err
	}
	if applied.TeamId != team || applied.ProjectKey != source.Key || applied.Name != name || applied.AppliedDefinitionRevision != revision.Revision || applied.MutationRevision < 1 || selected != nil && (applied.Id != selected.Id || applied.MutationRevision <= selected.MutationRevision) {
		return zero, invalidEnvironmentResponse()
	}
	return applied, nil
}

func invalidEnvironmentResponse() error {
	return failure.Wrap("read applied environment", failure.ServerResponseInvalid, errors.New("control returned another environment or definition"))
}
