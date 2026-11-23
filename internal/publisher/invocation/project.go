package invocation

import (
	"context"
	"errors"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/meta"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/client/team"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/config"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type projectConfiguration struct {
	clientproject.Project
	targetResolver target.TargetResolver
}

// ProjectRuntime composes publication operations with an app registration owner.
// it never starts a process or serves the private native API.
type ProjectRuntime struct {
	Telemetry         *clienttelemetry.Collector
	project           projectConfiguration
	state             *clientstate.Database
	manager           *publisherapp.Manager
	TargetResolver    target.TargetResolver
	AttachPublication func(context.Context, publisherapp.Service, *publisherservice.RunConfig) error
}

func NewProjectRuntime(project clientproject.Project, state *clientstate.Database, manager *publisherapp.Manager, resolver target.TargetResolver) *ProjectRuntime {
	return &ProjectRuntime{project: projectConfiguration{Project: project, targetResolver: resolver}, state: state, manager: manager, TargetResolver: resolver}
}

func (a *ProjectRuntime) Metadata(ctx context.Context) (meta.Metadata, error) {
	r := resolve.NewMetadataResolver(a.state, a.project.Project, authenticateRuntime)
	return r.Generate(ctx)
}

// prepare allocates only the selected local service and projects its returned
// endpoint. publication still waits for a registered app listener.
func (a *ProjectRuntime) PrepareLocalService(ctx context.Context, name string) (meta.Metadata, error) {
	if _, found := a.project.Config.Services[name]; !found || config.SelectedDeployment(a.project.Config) != "local" {
		return meta.Metadata{}, errors.New("preparation requires a selected local service")
	}
	effective, err := a.project.EffectiveService(name)
	if err != nil {
		return meta.Metadata{}, err
	}
	resolver := resolve.NewMetadataResolver(a.state, a.project.Project, authenticateRuntime)
	authenticated, current, err := resolver.Context(ctx, effective)
	if err != nil {
		return meta.Metadata{}, err
	}
	selected, err := a.realizeLocalService(ctx, authenticated, current, name)
	if err != nil {
		return meta.Metadata{}, err
	}
	return resolver.GenerateForLocalService(ctx, selected)
}

// preparation and registration must select the same address. opaque naming
// applies before the first allocation and never renames an existing service.
func (a *ProjectRuntime) realizeLocalService(ctx context.Context, authenticated *auth.Client, selected team.Context, name string) (controlv1.LocalProjectService, error) {
	project := a.project.Project
	request := LocalService{Project: project, Team: FromTeamContext(selected), Name: name, TargetResolver: a.TargetResolver}
	definition := project.Config.Services[name]
	if project.Config.Naming == "opaque" && config.Protocol(definition) == "http" && definition.Public != nil && *definition.Public {
		source := project.LocalPublicationIdentity()
		_, err := authenticated.Control.GetLocalProjectService(ctx, source.Key, name, controlv1.GetLocalProjectServiceParams{
			TeamId: selected.Team().Id, SourceFingerprint: source.Fingerprint, WorktreeKey: project.LocalWorktreeKey(),
		})
		if errors.Is(err, clientcontrol.ErrNotFound) {
			profile, err := a.state.Server(ctx, authenticated.ServerEndpoint)
			if err != nil {
				return controlv1.LocalProjectService{}, err
			}
			_, identity, err := previewPublisher(ctx, profile, authenticated, selected)
			if err != nil {
				return controlv1.LocalProjectService{}, err
			}
			request.PreviewPublisher = identity.ClientId
		} else if err != nil {
			return controlv1.LocalProjectService{}, err
		}
	}
	return RealizeLocalService(ctx, authenticated.Control, request)
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
