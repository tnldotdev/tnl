package resolve

import (
	"context"
	"errors"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type CollectionBackend interface {
	CreateServiceDefinition(context.Context, string, controlv1.CreateServiceDefinitionRequest) (controlv1.ServiceDefinitionRevision, error)
	ListCollections(context.Context, string, string) ([]controlv1.Collection, error)
	CreateCollection(context.Context, string, controlv1.CreateCollectionRequest) (controlv1.Collection, error)
	UpdateCollectionDefault(context.Context, string, string, controlv1.UpdateCollectionDefaultRequest) (controlv1.Collection, error)
}

// apply collection changes only the default for future members. no environment
// operation is available through this boundary, so installed members stay put.
func ApplyCollection(ctx context.Context, backend CollectionBackend, project clientproject.Project, team, name string) (controlv1.Collection, error) {
	var zero controlv1.Collection
	declared := project.Config
	if project.Declared != nil {
		declared = *project.Declared
	}
	if _, found := declared.Collections[name]; !found {
		return zero, errors.New("--collection must select a declared collection")
	}
	definition, err := Definition(project)
	if err != nil {
		return zero, err
	}
	source, err := project.SourceIdentity(ctx)
	if err != nil {
		return zero, err
	}
	collections, err := backend.ListCollections(ctx, team, source.Key)
	if err != nil {
		return zero, err
	}
	var selected *controlv1.Collection
	for _, value := range collections {
		if value.TeamId != team || value.ProjectKey != source.Key {
			return zero, invalidEnvironmentResponse()
		}
		if value.Name == name {
			if selected != nil {
				return zero, invalidEnvironmentResponse()
			}
			selected = &value
		}
	}
	revision, err := backend.CreateServiceDefinition(ctx, source.Key, controlv1.CreateServiceDefinitionRequest{TeamId: team, SourceFingerprint: source.Fingerprint, ProjectLabel: &source.Label, Definition: definition})
	if err != nil {
		return zero, err
	}
	if revision.TeamId != team || revision.ProjectKey != source.Key || revision.SourceFingerprint != source.Fingerprint || revision.Revision < 1 {
		return zero, invalidEnvironmentResponse()
	}
	var applied controlv1.Collection
	if selected == nil {
		applied, err = backend.CreateCollection(ctx, source.Key, controlv1.CreateCollectionRequest{TeamId: team, Name: name, DefaultDefinitionRevision: revision.Revision})
	} else {
		applied, err = backend.UpdateCollectionDefault(ctx, source.Key, selected.CollectionId, controlv1.UpdateCollectionDefaultRequest{TeamId: team, ExpectedRevision: selected.MutationRevision, DefinitionRevision: revision.Revision})
	}
	if err != nil {
		return zero, err
	}
	if applied.TeamId != team || applied.ProjectKey != source.Key || applied.Name != name || applied.DefaultDefinitionRevision != revision.Revision || applied.MutationRevision < 1 || selected != nil && (applied.CollectionId != selected.CollectionId || applied.MutationRevision <= selected.MutationRevision) {
		return zero, invalidEnvironmentResponse()
	}
	return applied, nil
}
