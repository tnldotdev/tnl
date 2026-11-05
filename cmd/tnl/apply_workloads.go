package main

import (
	"context"

	"github.com/tnldotdev/tnl/internal/client/project/workloadsetup"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func bindProjectWorkloads(ctx context.Context, project projectConfiguration, server string, declaration *controlv1.ProjectConfiguration, saved controlv1.ProjectConfiguration) error {
	if len(project.Config.Workloads) == 0 {
		return nil
	}
	previous := map[string]controlv1.ProjectWorkload{}
	if saved.Workloads != nil {
		previous = *saved.Workloads
	}
	policies, err := workloadsetup.Resolve(ctx, workloadsetup.Options{
		Directory: project.Root, Server: server, Workloads: project.Config.Workloads,
		Previous: previous, Repository: project.GitHubRepository,
	})
	if err != nil {
		return err
	}
	declaration.Workloads = &policies
	return nil
}
