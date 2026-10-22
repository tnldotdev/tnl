package invocation

import (
	"context"

	projectconfig "github.com/tnldotdev/tnl/internal/client/project"
	projectmeta "github.com/tnldotdev/tnl/internal/client/project/meta"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher"
	clientruntime "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/target"
)

type projectConfiguration struct {
	projectconfig.Project
	targetResolver target.TargetResolver
}

// ProjectRuntime composes publication operations with an app registration owner.
// it never starts a process or serves the private native API.
type ProjectRuntime struct {
	project           projectConfiguration
	state             *clientstate.Database
	manager           *clientruntime.Manager
	TargetResolver    target.TargetResolver
	AttachPublication func(context.Context, clientruntime.Service, *publisher.Config) error
}

func NewProjectRuntime(project projectconfig.Project, state *clientstate.Database, manager *clientruntime.Manager, resolver target.TargetResolver) *ProjectRuntime {
	return &ProjectRuntime{project: projectConfiguration{Project: project, targetResolver: resolver}, state: state, manager: manager, TargetResolver: resolver}
}

func (a *ProjectRuntime) Metadata(ctx context.Context) (projectmeta.Metadata, error) {
	r := resolve.NewMetadataResolver(a.state, a.project.Project, authenticateRuntime)
	return r.Generate(ctx)
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func effectiveTunnelLimits(effective config.TNL) *config.Limits {
	if effective.Tunnel == nil {
		return nil
	}
	return effective.Tunnel.Limits
}
