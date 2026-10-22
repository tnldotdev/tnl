package invocation

import (
	"context"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/publisher"
	clientruntime "github.com/tnldotdev/tnl/internal/publisher/app"
)

// integration workers share the entry tunnel's lifetime and namespace; each
// elected publisher obtains its own purpose-scoped native grant.
func attachRuntimeIntegrations(ctx context.Context, state *clientstate.Database, project clientproject.Project, service clientruntime.Service, tunnel *clientstate.Tunnel, cfg *publisher.Config) (func(), error) {
	if !project.Config.OAuth && len(project.Config.Webhooks) == 0 && len(project.Config.Aliases) == 0 {
		return nil, nil
	}
	server := cfg.ControlURL
	authenticated, err := authenticateRuntime(ctx, state, server)
	if err != nil {
		return nil, err
	}
	services, err := preparePublisherServices(ctx, state, server, "https://"+cfg.Hostname, "", "", valueOrEmpty(project.Config.Team), false, authenticated)
	if err != nil {
		return nil, err
	}
	group := projectIntegrationGroup(project, services.namespace)
	output := &Presentation{}
	var stops []func()
	if project.Config.OAuth {
		origin, oauthServices, err := projectOAuthPublisher(ctx, state, project, server, valueOrEmpty(project.Config.Team), authenticated)
		if err != nil {
			return nil, err
		}
		stops = append(stops, startOAuthIntegrationURL(ctx, state, oauthServices, origin, tunnel, output, nil))
	}
	if len(project.Config.Webhooks) != 0 {
		stops = append(stops, startWebhookIntegrationURL(ctx, state, services, project, tunnel, service.Name, group, output, nil))
	}
	if len(project.Config.Aliases) != 0 {
		stops = append(stops, startProjectAliases(ctx, state, projectConfiguration{Project: project}, service.Name, valueOrEmpty(project.Config.Team), services, *cfg, group, tunnel, output))
	}
	return func() {
		for i := len(stops) - 1; i >= 0; i-- {
			stops[i]()
		}
	}, nil
}
