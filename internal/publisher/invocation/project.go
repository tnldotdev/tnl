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
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
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
	AttachPublication func(context.Context, publisherapp.Service, *publisherservice.RunConfig) error
}

func NewProjectRuntime(project clientproject.Project, state *clientstate.Database, manager *publisherapp.Manager, resolver target.TargetResolver) *ProjectRuntime {
	return &ProjectRuntime{project: projectConfiguration{Project: project, targetResolver: resolver}, state: state, manager: manager, TargetResolver: resolver}
}

func (a *ProjectRuntime) Metadata(ctx context.Context) (meta.Metadata, error) {
	r := resolve.NewMetadataResolver(a.state, a.project.Project, authenticateRuntime)
	return r.Generate(ctx)
}

// PrepareLocalService allocates only the selected local service before reading
// its endpoint metadata. publication still waits for a registered app listener.
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
	if _, err := RealizeLocalService(ctx, authenticated.Control, LocalService{
		Project: a.project.Project, Team: FromTeamContext(current), Name: name, TargetResolver: a.TargetResolver,
	}); err != nil {
		return meta.Metadata{}, err
	}
	return resolver.Generate(ctx)
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
