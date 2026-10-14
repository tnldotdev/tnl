package main

import (
	"context"
	"fmt"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/dockertarget"
	"github.com/tnldotdev/tnl/internal/projectconfig"
)

func namedDynamicTarget(project projectconfig.Project, selected *config.ServiceTarget, protocol string) func(context.Context) (string, error) {
	if selected == nil {
		return nil
	}
	switch selected.Type {
	case "compose":
		return composeTarget(project, selected, protocol)
	case "docker":
		return func(ctx context.Context) (string, error) {
			address, err := dockertarget.ContainerPort(ctx, project.Root, project.Worktree.Label.FullLabel, *selected.Container, *selected.Port)
			if err != nil {
				return "", diagnostic.WrapMessage(diagnostic.TargetUnavailable,
					fmt.Sprintf("Docker container %q has no published host port for private port %d in this worktree; start the labeled container and publish its port", *selected.Container, *selected.Port), err)
			}
			if protocol == "http" {
				return "http://" + address, nil
			}
			return address, nil
		}
	default:
		return nil
	}
}
