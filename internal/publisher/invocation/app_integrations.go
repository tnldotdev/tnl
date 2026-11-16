package invocation

import (
	"context"
	"net/http"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/integrations"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// integration workers share the entry tunnel's lifetime and namespace; each
// elected publisher obtains an exact grant for its ordinary saved service.
func attachRuntimeIntegrations(ctx context.Context, state *clientstate.Database, project clientproject.Project, service publisherapp.Service, tunnel *clientstate.Tunnel, cfg *publisherservice.RunConfig) (func(), error) {
	if cfg.Metadata.Protocol != controlv1.ServiceProtocolHTTP {
		return nil, nil
	}
	if cfg.Control == nil {
		return nil, publisheridentity.ErrScope
	}
	server := cfg.Control.ControlURL()
	// a replacement must reject known returns even if OAuth was disabled in
	// its configuration. aliases compose their own admission, not this hook.
	previousAdmission := cfg.HTTPAdmitRequest
	admit := integrations.OAuthAdmission(state, server)
	cfg.HTTPAdmitRequest = func(request *http.Request, run publisherservice.HTTPRun) error {
		if previousAdmission != nil {
			if err := previousAdmission(request, run); err != nil {
				return err
			}
		}
		return admit(request, run)
	}
	if !project.Config.OAuth && len(project.Config.Webhooks) == 0 && len(project.Config.Aliases) == 0 {
		return nil, nil
	}
	if cfg.Access == nil {
		return nil, publisheridentity.ErrScope
	}
	access, err := cfg.Access(ctx)
	if err != nil {
		return nil, err
	}
	saved, err := cfg.Control.GetPublisherService(ctx, cfg.ServiceID, access)
	if err != nil {
		return nil, err
	}
	if saved.Id != cfg.ServiceID || !saved.Enabled || saved.Endpoint == nil || saved.DomainId == nil {
		return nil, publisheridentity.ErrScope
	}
	authenticated, err := authenticateRuntime(ctx, state, server)
	if err != nil {
		return nil, err
	}
	services, err := preparePublisherServices(ctx, state, server, "https://"+saved.Endpoint.Hostname, "", "", valueOrEmpty(project.Config.Team), false, authenticated)
	if err != nil {
		return nil, err
	}
	if services.teamID != saved.TeamId || services.domainID != *saved.DomainId {
		return nil, publisheridentity.ErrScope
	}
	group := projectIntegrationScope(project, services.namespace)
	if err := tunnel.SetIntegrationScope(ctx, group); err != nil {
		return nil, err
	}
	output := &Presentation{}
	telemetry := cfg.Telemetry.BeginScope("publisher")
	transferred := false
	defer func() {
		if !transferred {
			telemetry.Close()
		}
	}()
	var stops []func()
	if project.Config.OAuth {
		origin, oauthServices, err := projectOAuthPublisher(ctx, state, project, server, valueOrEmpty(project.Config.Team), authenticated)
		if err != nil {
			return nil, err
		}
		previous := cfg.HTTPResponseHooks
		observe := integrations.Observer(state, server, origin.Hostname, group, tunnel.ID())
		cfg.HTTPResponseHooks = func(run publisherservice.HTTPRun) httpstream.ResponseHooks {
			var hooks httpstream.ResponseHooks
			if previous != nil {
				hooks = previous(run)
			}
			prior := hooks.Observe
			hooks.Observe = func(response *http.Response) error {
				if prior != nil {
					if err := prior(response); err != nil {
						return err
					}
				}
				return observe(response, run)
			}
			return hooks
		}
		stops = append(stops, startOAuthIntegrationURL(ctx, state, oauthServices, origin, tunnel, output, telemetry))
	}
	if len(project.Config.Webhooks) != 0 {
		stops = append(stops, startWebhookIntegrationURL(ctx, state, services, project, tunnel, service.Name, group, output, telemetry))
	}
	if len(project.Config.Aliases) != 0 {
		stops = append(stops, startProjectAliases(ctx, state, projectConfiguration{Project: project}, service.Name, valueOrEmpty(project.Config.Team), services, *cfg, group, tunnel, output))
	}
	transferred = true
	return func() {
		defer telemetry.Close()
		for i := len(stops) - 1; i >= 0; i-- {
			stops[i]()
		}
	}, nil
}
