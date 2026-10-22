package local

import (
	projectconfig "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	localproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
)

func (a *appRuntime) resolveRuntimeMounts(project projectconfig.Project, service string) ([]localproxy.Mount, error) {
	return invocation.ProjectMounts(project, service, func(name string) string {
		for _, candidate := range a.manager.Snapshot().Services {
			if candidate.Name == name && a.manager.Current(name, candidate.RegistrationID, candidate.Target, 0) {
				return candidate.Target
			}
		}
		return ""
	}, a.resolver())
}
