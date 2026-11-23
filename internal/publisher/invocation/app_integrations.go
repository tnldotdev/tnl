package invocation

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"github.com/tnldotdev/tnl/internal/client/auth"
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
func attachRuntimeIntegrations(ctx context.Context, state *clientstate.Database, project clientproject.Project, service publisherapp.Service, tunnel *clientstate.Tunnel, cfg *publisherservice.RunConfig) (func() error, error) {
	var authenticated *auth.Client
	if cfg.Metadata.Protocol == controlv1.ServiceProtocolHTTP && projectHasIntegrations(project) {
		if cfg.Control == nil {
			return nil, publisheridentity.ErrScope
		}
		var err error
		authenticated, err = authenticateRuntime(ctx, state, cfg.Control.ControlURL())
		if err != nil {
			return nil, err
		}
	}
	return attachIntegrations(ctx, state, project, service, tunnel, cfg, valueOrEmpty(project.Config.Team), authenticated)
}

func projectHasIntegrations(project clientproject.Project) bool {
	return project.Config.OAuth || len(project.Config.Webhooks) != 0 || len(project.Config.Aliases) != 0
}

// foreground callers retain their authenticated client and selected team;
// app-led callers authenticate their captured runtime context before attachment.
func attachIntegrations(ctx context.Context, state *clientstate.Database, project clientproject.Project, service publisherapp.Service, tunnel *clientstate.Tunnel, cfg *publisherservice.RunConfig, selectedTeam string, authenticated *auth.Client) (func() error, error) {
	if cfg.Metadata.Protocol != controlv1.ServiceProtocolHTTP {
		return nil, nil
	}
	if cfg.Control == nil {
		return nil, publisheridentity.ErrScope
	}
	server := cfg.Control.ControlURL()
	// a replacement must reject known returns even if OAuth was disabled in
	// its configuration. aliases compose their own admission, not this hook.
	previousPreparation := cfg.HTTPPrepareRequest
	prepare := integrations.PrepareOAuthReturn(state, server)
	cfg.HTTPPrepareRequest = func(request *http.Request, run publisherservice.HTTPRun) (func(context.Context) error, error) {
		var prior func(context.Context) error
		if previousPreparation != nil {
			var err error
			prior, err = previousPreparation(request, run)
			if err != nil {
				return nil, err
			}
		}
		consume, err := prepare(request, run)
		if err != nil {
			return nil, err
		}
		if prior == nil {
			return consume, nil
		}
		return func(ctx context.Context) error {
			if err := prior(ctx); err != nil {
				return err
			}
			if consume != nil {
				return consume(ctx)
			}
			return nil
		}, nil
	}
	if !projectHasIntegrations(project) {
		return nil, nil
	}
	if cfg.Access == nil || authenticated == nil || authenticated.ServerEndpoint != server {
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
	services, err := preparePublisherServices(ctx, state, server, "https://"+saved.Endpoint.Hostname, "", "", selectedTeam, false, authenticated, false)
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
	shutdown := integrationShutdown{deadline: cfg.ShutdownDeadline, fence: cfg.ShutdownContext}
	return attachIntegrationWorkers(ctx, telemetry.Close, func(ctx context.Context, add func(func() error)) error {
		if project.Config.OAuth {
			origin, oauthServices, err := projectOAuthPublisher(ctx, state, project, server, services.teamID, authenticated)
			if err != nil {
				return err
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
			add(startOAuthIntegrationURL(ctx, state, oauthServices, origin, tunnel, output, telemetry, shutdown))
		}
		if len(project.Config.Webhooks) != 0 {
			add(startWebhookIntegrationURL(ctx, state, services, project, tunnel, service.Name, group, output, telemetry, shutdown))
		}
		if len(project.Config.Aliases) != 0 {
			add(startProjectAliases(ctx, state, projectConfiguration{Project: project}, service.Name, services.teamID, services, *cfg, group, tunnel, output))
		}
		return nil
	})
}

// attachment owns every started worker even when later setup fails. one stop
// cancels all siblings before joining them, then closes their telemetry scope.
func attachIntegrationWorkers(ctx context.Context, finished func(), attach func(context.Context, func(func() error)) error) (stop func() error, result error) {
	ctx, cancel := context.WithCancel(ctx)
	var stops []func() error
	join := sync.OnceValue(func() error {
		cancel()
		defer finished()
		var result error
		for i := len(stops) - 1; i >= 0; i-- {
			result = errors.Join(result, stops[i]())
		}
		return result
	})
	transferred := false
	defer func() {
		if !transferred {
			result = errors.Join(result, join())
		}
	}()
	if err := attach(ctx, func(stop func() error) { stops = append(stops, stop) }); err != nil {
		return nil, err
	}
	transferred = true
	return join, nil
}
