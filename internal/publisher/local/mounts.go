package local

import (
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
)

func (a *appRuntime) resolveRuntimeMounts(project clientproject.Project, service string) ([]publisherproxy.Mount, error) {
	return invocation.ProjectMounts(project, service, func(name string) string {
		for _, candidate := range a.manager.Snapshot().Services {
			if candidate.Name == name && a.manager.CurrentRegistration(name, candidate.RegistrationID, candidate.Target) {
				return candidate.Target
			}
		}
		return ""
	}, a.resolver())
}
