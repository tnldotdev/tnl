package local

import (
	"context"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
)

func (a *appRuntime) resolveRuntimeMounts(ctx context.Context, project clientproject.Project, service string) ([]publisherproxy.Mount, error) {
	return invocation.ProjectMounts(ctx, project, service, func(name string) string {
		for _, candidate := range a.manager.Snapshot().Services {
			if candidate.Name == name && a.manager.CurrentRegistration(name, candidate.RegistrationID, candidate.Target) {
				return candidate.Target
			}
		}
		return ""
	}, a.resolver())
}
