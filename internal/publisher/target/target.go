// package target resolves private targets independently of placement.
package target

import (
	"context"
	"errors"

	projectconfig "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
)

// TargetResolver must verify exact container identity, Compose project/service
// labels and worktree placement before returning a private address.
type TargetResolver interface {
	ResolveTarget(context.Context, projectconfig.Project, string) (string, error)
}

type TargetResolverFunc func(context.Context, projectconfig.Project, string) (string, error)

func (f TargetResolverFunc) ResolveTarget(ctx context.Context, p projectconfig.Project, name string) (string, error) {
	return f(ctx, p, name)
}

func ResolveTarget(ctx context.Context, project projectconfig.Project, name string, discovery TargetResolver) (*config.Publish, error) {
	service, found := project.Config.Services[name]
	if !found {
		return nil, errors.New("service is not configured")
	}
	if config.TargetType(service) == "app" {
		return nil, errors.New("app target requires a bound listener registration")
	}
	address := ""
	if config.TargetType(service) != "address" {
		if discovery == nil {
			return nil, errors.New("container target resolver is required")
		}
		var err error
		address, err = discovery.ResolveTarget(ctx, project, name)
		if err != nil {
			return nil, err
		}
	}
	return project.ResolvePublish(name, address)
}
