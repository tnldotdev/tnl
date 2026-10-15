package main

import (
	"context"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/projectpublisher"
)

func runtimeTargetBinding(project projectconfig.Project, name string, placement *runtimeComposePlacement, reported string, changed func()) *projectpublisher.TargetBinding {
	return &projectpublisher.TargetBinding{Changed: changed, Resolve: func(ctx context.Context) (projectpublisher.TargetSnapshot, error) {
		if placement != nil && config.TargetType(project.Config.Services[name]) == "app" {
			app, found := placement.Setup.Apps[name]
			if !found {
				return projectpublisher.TargetSnapshot{}, privateprotocol.ErrForbidden
			}
			address, identity, err := placement.Resolver.ResolveAppIdentity(ctx, project, placement.Setup.Project, placement.Setup.File, app.Service, reported)
			return projectpublisher.TargetSnapshot{Address: address, Identity: identity}, err
		}
		if reported != "" && config.TargetType(project.Config.Services[name]) == "app" {
			address, err := localproxy.NormalizeTarget(reported)
			return projectpublisher.TargetSnapshot{Address: address, Identity: address}, err
		}
		return projectpublisher.ResolveTargetSnapshot(ctx, project, name, runtimeTargetResolver)
	}}
}
