package main

import (
	"context"
	"fmt"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/dockertarget"
	"github.com/tnldotdev/tnl/internal/projectconfig"
)

// composeTarget resolves the current host port from the selected worktree's
// explicit Compose project and file. no host port is saved in configuration.
func composeTarget(project projectconfig.Project, selected *config.ServiceTarget, protocol string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		address, err := dockertarget.ComposePort(ctx, project.Root, *selected.File, *selected.Project, *selected.Service, *selected.Port)
		if err != nil {
			return "", diagnostic.WrapMessage(diagnostic.TargetUnavailable,
				fmt.Sprintf("Compose service %q has no published host port; start project %q with file %q and publish private port %d", *selected.Service, *selected.Project, *selected.File, *selected.Port), err)
		}
		if protocol == "http" {
			return "http://" + address, nil
		}
		return address, nil
	}
}
