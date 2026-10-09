package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
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

func projectIntegrationGroup(project projectconfig.Project, namespace string) string {
	return projectconfig.SharedProjectIdentity(project.Worktree, project.Root) + "\x00" + namespace
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

func integrationURLConfig(services publisherServices, hostname string, purpose controlv1.PublicURLCreatePurpose) publisher.Config {
	config := services.config(integrationURLTarget, []string{}, 32)
	config.Hostname, config.PublicURLScope, config.Ephemeral = hostname, controlv1.Member, false
	config.Purpose = purpose
	return config
}

func reportIntegrationURL(tunnel *clientstate.Tunnel, output *publishOutput, state, footer string, blocks ...clioutput.Block) {
	if err := output.integrationURLMessage(state, footer, blocks...); err != nil {
		tunnel.CancelWithCause(failure.Wrap("write integration URL progress", failure.OutputUnavailable, err))
	}
}

func startOAuthIntegrationURL(ctx context.Context, state *clientstate.Database, services publisherServices, oauth projectmeta.IntegrationOrigin, tunnel *clientstate.Tunnel, output *publishOutput, telemetry telemetryReporter) func() {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	var reportMu sync.Mutex
	lastReport := time.Time{}
	integrationURLPublisher := integrationurls.Publisher{
		State: state, Store: services.state, Server: services.authenticated.ServerEndpoint, Hostname: oauth.Hostname,
		Prepare: func(context.Context) (integrationurls.Snapshot, error) {
			config := integrationURLConfig(services, oauth.Hostname, controlv1.PublicURLCreatePurposeOauth)
			config.Handler = integrationurls.OAuthHandler(state, services.authenticated.ServerEndpoint, oauth.Hostname, func() {
				if telemetry != nil {
					telemetry.Report(newIntegrationTelemetry(telemetryOAuthRedirected, ""))
				}
			})
			return integrationurls.Snapshot{Config: config}, nil
		},
		Report: func(event publisher.Event, err error) {
			reportMu.Lock()
			defer reportMu.Unlock()
			if err != nil {
				if time.Since(lastReport) >= 30*time.Second {
					lastReport = time.Now()
					reportIntegrationURL(tunnel, output, "oauth unavailable", "app tunnel continues; retry sign-in shortly", clioutput.Text("the callback publisher could not become ready"))
				}
			} else if event.Type == publisher.EventReady {
				if telemetry != nil {
					telemetry.Report(newIntegrationTelemetry(telemetryOAuthReady, ""))
				}
				reportIntegrationURL(tunnel, output, "oauth ready", "", clioutput.Fields(clioutput.Field{Label: "oauth origin", Value: oauth.URL}))
			}
		},
	}
	go func() { defer close(done); integrationURLPublisher.Maintain(ctx) }()
	return func() { cancel(); <-done }
}

func startWebhookIntegrationURL(ctx context.Context, state *clientstate.Database, services publisherServices, project projectconfig.Project, tunnel *clientstate.Tunnel, service, group string, output *publishOutput, telemetry telemetryReporter) func() {
	if len(project.Config.Webhooks) == 0 {
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	names := make([]string, 0, len(project.Config.Webhooks))
	for name, definition := range project.Config.Webhooks {
		if definition.Service == service {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		cancel()
		return func() {}
	}
	slices.Sort(names)
	registered := make(map[string]config.Webhook, len(names))
	for _, name := range names {
		encoded, _, err := integrationurls.DefinitionBytes(project.Config.Webhooks[name])
		if err == nil {
			err = tunnel.RegisterWebhookEndpoint(ctx, name, encoded)
		}
		if err == nil {
			registered[name] = project.Config.Webhooks[name]
		}
		if err != nil {
			state := "webhook unavailable"
			message := "webhook " + name + " could not register"
			if errors.Is(err, clientstate.ErrWebhookPolicyConflict) {
				state = "webhook policy conflict"
				message = "webhook " + name + " conflicts with another worktree's endpoint policy"
			}
			reportIntegrationURL(tunnel, output, state, "app tunnel continues", clioutput.Text(message))
		}
	}
	hooks, err := projectIntegrationOrigin(ctx, state, project, services.authenticated.ServerEndpoint, services.namespace, "hooks")
	if err != nil {
		reportIntegrationURL(tunnel, output, "webhooks unavailable", "app tunnel continues", clioutput.Text("the stable webhook origin could not be selected"))
		cancel()
		return func() {}
	}
	var workers sync.WaitGroup
	worker := webhookURLPublisher(state, services, group, hooks, tunnel, output, telemetry)
	workers.Go(func() { worker.Maintain(ctx) })
	if telemetry != nil && len(registered) != 0 {
		workers.Go(func() {
			watchWebhookReady(ctx, state, services.authenticated.ServerEndpoint, group, hooks.Hostname, registered, telemetry)
		})
	}
	return func() { cancel(); workers.Wait() }
}

func watchWebhookReady(ctx context.Context, state *clientstate.Database, server, group, hostname string, definitions map[string]config.Webhook, telemetry telemetryReporter) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		if mode := readyWebhookDelivery(ctx, state, server, group, hostname, definitions); mode != "" {
			telemetry.Report(newIntegrationTelemetry(telemetryWebhookReady, mode))
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func readyWebhookDelivery(ctx context.Context, state *clientstate.Database, server, group, hostname string, definitions map[string]config.Webhook) telemetryWebhookDelivery {
	ready, err := state.IntegrationURLReady(ctx, server, hostname)
	if err != nil || !ready {
		return ""
	}
	for _, name := range slices.Sorted(maps.Keys(definitions)) {
		definition := definitions[name]
		_, digest, err := integrationurls.DefinitionBytes(definition)
		if err != nil {
			continue
		}
		if definition.Delivery == "exclusive" {
			receiver, err := state.ExclusiveWebhookReceiver(ctx, server, group, name, digest)
			if err == nil && receiver.ID != "" {
				return telemetryExclusive
			}
			continue
		}
		receivers, err := state.WebhookReceivers(ctx, server, group, name, digest)
		if err == nil && len(receivers) != 0 {
			return telemetryFanout
		}
	}
	return ""
}

func webhookURLPublisher(state *clientstate.Database, services publisherServices, group string, origin projectmeta.IntegrationOrigin, tunnel *clientstate.Tunnel, output *publishOutput, telemetry telemetryReporter) integrationurls.Publisher {
	var reportMu sync.Mutex
	lastReport := time.Time{}
	failure := func(message string) {
		reportMu.Lock()
		defer reportMu.Unlock()
		if time.Since(lastReport) >= 30*time.Second {
			lastReport = time.Now()
			reportIntegrationURL(tunnel, output, "webhook unavailable", "app tunnel continues", clioutput.Text(message))
		}
	}
	definitionsAt := func(ctx context.Context) (map[string]config.Webhook, string, error) {
		definitions, err := state.ActiveWebhookDefinitions(ctx, services.authenticated.ServerEndpoint, group)
		if err != nil {
			return nil, "", err
		}
		if len(definitions) == 0 {
			return nil, "", errors.New("no active webhook declarations")
		}
		encoded, err := json.Marshal(definitions)
		if err != nil {
			return nil, "", err
		}
		digest := sha256.Sum256(encoded)
		return definitions, hex.EncodeToString(digest[:]), nil
	}
	return integrationurls.Publisher{
		State: state, Store: services.state, Server: services.authenticated.ServerEndpoint, Hostname: origin.Hostname,
		Prepare: func(ctx context.Context) (integrationurls.Snapshot, error) {
			definitions, revision, err := definitionsAt(ctx)
			if err != nil {
				return integrationurls.Snapshot{}, err
			}
			handler, prefixes, err := integrationurls.NewWebhooks(ctx, state, services.authenticated.ServerEndpoint, group, origin.Hostname, definitions,
				func(endpoint, receiver, reason string) { failure(endpoint + " to " + receiver + ": " + reason) })
			if err != nil {
				return integrationurls.Snapshot{}, err
			}
			if telemetry != nil {
				handler.OnReceiverResponse = func(mode string) {
					telemetry.Report(newIntegrationTelemetry(telemetryWebhookReady, telemetryWebhookDelivery(mode)))
					telemetry.Report(newIntegrationTelemetry(telemetryWebhookReached, telemetryWebhookDelivery(mode)))
				}
			}
			config := integrationURLConfig(services, origin.Hostname, controlv1.PublicURLCreatePurposeWebhooks)
			config.Handler, config.AllowedIPPrefixes = handler, prefixes
			return integrationurls.Snapshot{Config: config, Revision: revision}, nil
		},
		Revision: func(ctx context.Context) (string, error) {
			_, revision, err := definitionsAt(ctx)
			return revision, err
		},
		Report: func(event publisher.Event, err error) {
			if err != nil {
				failure("the stable webhook publisher could not become ready")
			} else if event.Type == publisher.EventReady {
				reportIntegrationURL(tunnel, output, "webhooks ready", "", clioutput.Fields(clioutput.Field{Label: "webhook origin", Value: origin.URL}))
			}
		},
	}
}
