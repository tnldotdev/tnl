package invocation

import (
	"context"
	"errors"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/meta"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/target"
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
	AttachPublication func(context.Context, publisherapp.Service, *publisher.Config) error
}

func NewProjectRuntime(project clientproject.Project, state *clientstate.Database, manager *publisherapp.Manager, resolver target.TargetResolver) *ProjectRuntime {
	return &ProjectRuntime{project: projectConfiguration{Project: project, targetResolver: resolver}, state: state, manager: manager, TargetResolver: resolver}
}

func (a *ProjectRuntime) Metadata(ctx context.Context) (meta.Metadata, error) {
	r := resolve.NewMetadataResolver(a.state, a.project.Project, authenticateRuntime)
	return r.Generate(ctx)
}

// app preparation may reserve its selected public endpoint before the app binds
// a listener. metadata reads remain read-only and no service run starts here.
func (a *ProjectRuntime) PrepareAppMetadata(ctx context.Context, name string) (meta.Metadata, error) {
	r := resolve.NewMetadataResolver(a.state, a.project.Project, authenticateRuntime)
	definition, found := a.project.Config.Services[name]
	public := found && config.SelectedDeployment(a.project.Config) == "local" &&
		config.TargetType(definition) == "app" && config.Protocol(definition) == "http" &&
		!config.IsPublicService(definition) && definition.Public != nil && *definition.Public
	if public {
		effective, err := a.project.EffectiveService(name)
		if err != nil {
			return meta.Metadata{}, err
		}
		client, current, err := r.Context(ctx, effective)
		if err != nil {
			return meta.Metadata{}, err
		}
		if _, err := RealizeLocalService(ctx, client.Control, LocalService{
			Project: a.project.Project, Team: FromTeamContext(current), Name: name,
		}); err != nil {
			return meta.Metadata{}, err
		}
	}
	metadata, err := r.Generate(ctx)
	if err != nil {
		return meta.Metadata{}, err
	}
	if selected, found := metadata.Services[name]; public && (!found || !selected.Public || selected.Protocol != "http") {
		return meta.Metadata{}, failure.Wrap("prepare local app endpoint", failure.ServerConflict, errors.New("local service endpoint changed during preparation; retry with the current project configuration"))
	}
	return metadata, nil
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func effectiveTunnelLimits(effective clientproject.ResolvedService) *config.Limits {
	if effective.Tunnel == nil {
		return nil
	}
	return effective.Tunnel.Limits
}
