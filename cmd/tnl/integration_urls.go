package main

import (
	"context"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/integrationurls"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/projectmeta"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// control records a loopback target; integration URL requests are handled directly
// after visitor TLS terminates in the publisher, without dialing this target.
const integrationURLTarget = "http://127.0.0.1:1"

func projectIntegrationOrigin(ctx context.Context, state *clientstate.Database, project projectconfig.Project, server, namespace, purpose string) (projectmeta.IntegrationOrigin, error) {
	salt, err := state.WorktreeHashSalt(ctx)
	if err != nil {
		return projectmeta.IntegrationOrigin{}, err
	}
	proposed := projectconfig.SharedProjectLabel(purpose, project.Worktree, project.Root, salt) + "." + namespace
	hostname, err := state.IntegrationURLHostname(ctx, server, projectconfig.SharedProjectIdentity(project.Worktree, project.Root), namespace, purpose, proposed)
	if err != nil {
		return projectmeta.IntegrationOrigin{}, err
	}
	return projectmeta.IntegrationOrigin{Hostname: hostname, URL: "https://" + hostname}, nil
}

// projectOAuthPublisher selects the project domain even when the app service
// overrides its domain. the provider registers only one callback URL.
func projectOAuthPublisher(ctx context.Context, state *clientstate.Database, project projectconfig.Project, server, team string, authenticated *clientauth.Client) (projectmeta.IntegrationOrigin, publisherServices, error) {
	domain := ""
	if project.Config.Tunnel != nil && project.Config.Tunnel.Domain != nil {
		domain = *project.Config.Tunnel.Domain
	}
	services, err := preparePublisherServices(ctx, state, server, "", "", domain, team, false, authenticated)
	if err != nil {
		return projectmeta.IntegrationOrigin{}, publisherServices{}, err
	}
	origin, err := projectIntegrationOrigin(ctx, state, project, server, services.namespace, "oauth")
	return origin, services, err
}

func integrationURLConfig(services publisherServices, hostname string) publisher.Config {
	config := services.config(integrationURLTarget, []string{}, 32)
	config.Hostname, config.PublicURLScope, config.Ephemeral = hostname, controlv1.Member, false
	return config
}

func startOAuthIntegrationURL(ctx context.Context, state *clientstate.Database, services publisherServices, oauth projectmeta.IntegrationOrigin, output *publishOutput) func() {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	var reportMu sync.Mutex
	lastReport := time.Time{}
	integrationURLPublisher := integrationurls.Publisher{
		State: state, Store: services.state, Server: services.authenticated.ServerEndpoint, Hostname: oauth.Hostname,
		Prepare: func(context.Context) (integrationurls.Snapshot, error) {
			config := integrationURLConfig(services, oauth.Hostname)
			config.Handler = integrationurls.OAuthHandler(state, services.authenticated.ServerEndpoint, oauth.Hostname)
			return integrationurls.Snapshot{Config: config}, nil
		},
		Report: func(event publisher.Event, err error) {
			reportMu.Lock()
			defer reportMu.Unlock()
			if err != nil {
				if time.Since(lastReport) >= 30*time.Second {
					lastReport = time.Now()
					_ = output.integrationURLMessage("oauth unavailable", "app tunnel continues; retry sign-in shortly", clioutput.Text("the callback publisher could not become ready"))
				}
			} else if event.Type == publisher.EventReady {
				_ = output.integrationURLMessage("oauth ready", "", clioutput.Fields(clioutput.Field{Label: "oauth origin", Value: oauth.URL}))
			}
		},
	}
	go func() { defer close(done); integrationURLPublisher.Maintain(ctx) }()
	return func() { cancel(); <-done }
}
