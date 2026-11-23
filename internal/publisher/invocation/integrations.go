package invocation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/meta"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/publisher/integrations"
	telemetryv1 "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

func projectIntegrationScope(project clientproject.Project, namespace string) clientstate.IntegrationScope {
	return clientstate.IntegrationScope{PrimaryProjectRoot: clientproject.SharedProjectIdentity(project.Worktree, project.Root), Namespace: namespace}
}

// projectOAuthPublisher selects the project domain even when the app service
// overrides its domain. the provider registers only one callback URL.
func projectOAuthPublisher(ctx context.Context, state *clientstate.Database, project clientproject.Project, server, team string, authenticated *auth.Client) (meta.IntegrationOrigin, publisherServices, error) {
	domain := ""
	if project.Config.DeploymentSettings.Domain != nil {
		domain = *project.Config.DeploymentSettings.Domain
	}
	services, err := preparePublisherServices(ctx, state, server, "", "", domain, team, false, authenticated, false)
	if err != nil {
		return meta.IntegrationOrigin{}, publisherServices{}, err
	}
	origin, err := resolve.IntegrationOrigin(ctx, state, project, server, services.namespace, "oauth")
	return origin, services, err
}

func reportIntegrationURL(tunnel *clientstate.Tunnel, output *Presentation, state, footer string, blocks ...clioutput.Block) {
	if err := output.integrationURLMessage(state, footer, blocks...); err != nil {
		tunnel.CancelWithCause(failure.Wrap("write integration URL progress", failure.OutputUnavailable, err))
	}
}

// startIntegrationWorkers owns one cancellation and joins every worker before
// returning its result. repeated stops observe the same joined result.
func startIntegrationWorkers(ctx context.Context, workers ...func(context.Context) error) func() error {
	ctx, cancel := context.WithCancel(ctx)
	var joined sync.WaitGroup
	results := make([]error, len(workers))
	for index, worker := range workers {
		joined.Go(func() { results[index] = worker(ctx) })
	}
	return sync.OnceValue(func() error {
		cancel()
		joined.Wait()
		return errors.Join(results...)
	})
}

func startOAuthIntegrationURL(ctx context.Context, state *clientstate.Database, services publisherServices, oauth meta.IntegrationOrigin, tunnel *clientstate.Tunnel, output *Presentation, telemetry *clienttelemetry.Scope, shutdown integrationShutdown) func() error {
	var reportMu sync.Mutex
	lastReport := time.Time{}
	integrationURLPublisher := integrations.Publisher{
		State: state, Store: services.state, Server: services.authenticated.ServerEndpoint, Hostname: oauth.Hostname,
		Prepare: func(ctx context.Context) (integrations.Snapshot, error) {
			config, saved, err := nativeIntegrationConfig(ctx, services, oauth.Hostname, targetsyntax.OAuthIntegration, nil, shutdown)
			if err != nil {
				return integrations.Snapshot{}, err
			}
			config.Handler = integrations.OAuthHandler(state, services.authenticated.ServerEndpoint, oauth.Hostname, func() {
				telemetry.Integration(telemetryv1.IntegrationOutcome{Kind: "oauth", Outcome: telemetryv1.Redirected})
			})
			return integrations.Snapshot{Config: config, Service: saved}, nil
		},
		Report: func(ready bool, err error) {
			reportMu.Lock()
			defer reportMu.Unlock()
			if err != nil {
				if time.Since(lastReport) >= 30*time.Second {
					lastReport = time.Now()
					reportIntegrationURL(tunnel, output, "oauth unavailable", "app tunnel continues; retry sign-in shortly", clioutput.Text("the callback publisher could not become ready"))
				}
			} else if ready {
				telemetry.Integration(telemetryv1.IntegrationOutcome{Kind: "oauth", Outcome: telemetryv1.Ready})
				reportIntegrationURL(tunnel, output, "oauth ready", "", clioutput.Fields(clioutput.Field{Label: "oauth origin", Value: oauth.URL}))
			}
		},
	}
	return startIntegrationWorkers(ctx, integrationURLPublisher.Maintain)
}

func startWebhookIntegrationURL(ctx context.Context, state *clientstate.Database, services publisherServices, project clientproject.Project, tunnel *clientstate.Tunnel, service string, group clientstate.IntegrationScope, output *Presentation, telemetry *clienttelemetry.Scope, shutdown integrationShutdown) func() error {
	if len(project.Config.Webhooks) == 0 {
		return func() error { return nil }
	}
	names := make([]string, 0, len(project.Config.Webhooks))
	for name, definition := range project.Config.Webhooks {
		if definition.Service == service {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return func() error { return nil }
	}
	slices.Sort(names)
	registered := make(map[string]config.Webhook, len(names))
	for _, name := range names {
		encoded, _, err := integrations.DefinitionBytes(project.Config.Webhooks[name])
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
	hooks, err := resolve.IntegrationOrigin(ctx, state, project, services.authenticated.ServerEndpoint, services.namespace, "hooks")
	if err != nil {
		reportIntegrationURL(tunnel, output, "webhooks unavailable", "app tunnel continues", clioutput.Text("the stable webhook origin could not be selected"))
		return func() error { return nil }
	}
	for _, name := range slices.Sorted(maps.Keys(registered)) {
		definition := registered[name]
		policy := "checking provider policy"
		if definition.SourceIPs != nil {
			policy = "source_ips override"
		} else if definition.Provider == "custom" {
			policy = "all sources"
		}
		reportIntegrationURL(tunnel, output, "webhook configured", "", clioutput.Fields(
			clioutput.Field{Label: "webhook", Value: name},
			clioutput.Field{Label: "public URL", Value: hooks.URL + definition.Path},
			clioutput.Field{Label: "delivery", Value: definition.DeliveryMode()},
			clioutput.Field{Label: "source policy", Value: policy},
			clioutput.Field{Label: "guide", Value: "https://tnl.dev/w/" + definition.Provider},
		))
	}
	worker := webhookURLPublisher(state, services, group, hooks, tunnel, output,
		func(ctx context.Context, definitions map[string]config.Webhook, report func(string, string, string)) (webhookSourceHandler, []string, error) {
			handler, prefixes, err := integrations.NewWebhooks(ctx, state, services.authenticated.ServerEndpoint, group, hooks.Hostname, definitions, report)
			if err == nil && telemetry != nil {
				handler.OnReceiverResponse = func(mode string) {
					delivery := telemetryv1.IntegrationOutcomeDelivery(mode)
					telemetry.Integration(telemetryv1.IntegrationOutcome{Kind: "webhook", Outcome: telemetryv1.Ready, Delivery: &delivery})
					telemetry.Integration(telemetryv1.IntegrationOutcome{Kind: "webhook", Outcome: telemetryv1.ReachedReceiver, Delivery: &delivery})
				}
			}
			return handler, prefixes, err
		}, shutdown)
	workers := []func(context.Context) error{worker.Maintain}
	if telemetry != nil && len(registered) != 0 {
		workers = append(workers, func(ctx context.Context) error {
			watchWebhookReady(ctx, state, services.authenticated.ServerEndpoint, group, hooks.Hostname, registered, telemetry)
			return nil
		})
	}
	return startIntegrationWorkers(ctx, workers...)
}

func watchWebhookReady(ctx context.Context, state *clientstate.Database, server string, group clientstate.IntegrationScope, hostname string, definitions map[string]config.Webhook, telemetry *clienttelemetry.Scope) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		if mode := readyWebhookDelivery(ctx, state, server, group, hostname, definitions); mode != "" {
			telemetry.Integration(telemetryv1.IntegrationOutcome{Kind: "webhook", Outcome: telemetryv1.Ready, Delivery: &mode})
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func readyWebhookDelivery(ctx context.Context, state *clientstate.Database, server string, group clientstate.IntegrationScope, hostname string, definitions map[string]config.Webhook) telemetryv1.IntegrationOutcomeDelivery {
	ready, err := state.IntegrationURLReady(ctx, server, hostname)
	if err != nil || !ready {
		return ""
	}
	for _, name := range slices.Sorted(maps.Keys(definitions)) {
		definition := definitions[name]
		_, digest, err := integrations.DefinitionBytes(definition)
		if err != nil {
			continue
		}
		if definition.DeliveryMode() == "selected" {
			receiver, err := state.ExclusiveWebhookReceiver(ctx, server, group, name, digest)
			if err == nil && receiver.ID != "" {
				return telemetryv1.Selected
			}
			continue
		}
		receivers, err := state.WebhookReceivers(ctx, server, group, name, digest)
		if err == nil && len(receivers) != 0 {
			return telemetryv1.Fanout
		}
	}
	return ""
}

// the source owner supplies current path checks and refresh; invocation only
// composes its coarse service-union write into the existing publisher tick.
type webhookSourceHandler interface {
	http.Handler
	PolicyStatus(string) string
	HasAvailablePolicy() bool
	RefreshPolicies(context.Context, func(context.Context, []string) error) error
}

func webhookURLPublisher(state *clientstate.Database, services publisherServices, group clientstate.IntegrationScope, origin meta.IntegrationOrigin, tunnel *clientstate.Tunnel, output *Presentation, prepare func(context.Context, map[string]config.Webhook, func(string, string, string)) (webhookSourceHandler, []string, error), shutdown integrationShutdown) integrations.Publisher {
	var active webhookSourceHandler
	var activeRevision string
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
	return integrations.Publisher{
		State: state, Store: services.state, Server: services.authenticated.ServerEndpoint, Hostname: origin.Hostname,
		Prepare: func(ctx context.Context) (integrations.Snapshot, error) {
			definitions, revision, err := definitionsAt(ctx)
			if err != nil {
				return integrations.Snapshot{}, err
			}
			handler, prefixes, err := prepare(ctx, definitions,
				func(endpoint, receiver, reason string) { failure(endpoint + " to " + receiver + ": " + reason) })
			if err != nil {
				return integrations.Snapshot{}, err
			}
			if !handler.HasAvailablePolicy() {
				return integrations.Snapshot{}, errors.New("no webhook endpoint has an available source policy")
			}
			for _, name := range slices.Sorted(maps.Keys(definitions)) {
				reportIntegrationURL(tunnel, output, "webhook policy", "", clioutput.Fields(
					clioutput.Field{Label: "webhook", Value: name},
					clioutput.Field{Label: "source policy", Value: handler.PolicyStatus(name)},
				))
			}
			config, saved, err := nativeIntegrationConfig(ctx, services, origin.Hostname, targetsyntax.WebhookIntegration, prefixes, shutdown)
			if err != nil {
				return integrations.Snapshot{}, err
			}
			config.Handler = handler
			active = handler
			activeRevision = revision
			return integrations.Snapshot{Config: config, Service: saved, Revision: revision}, nil
		},
		Revision: func(ctx context.Context) (string, error) {
			_, revision, err := definitionsAt(ctx)
			if err == nil && active != nil && revision == activeRevision {
				refreshErr := active.RefreshPolicies(ctx, func(ctx context.Context, prefixes []string) error {
					_, _, err := nativeIntegrationConfig(ctx, services, origin.Hostname, targetsyntax.WebhookIntegration, prefixes, shutdown)
					return err
				})
				if refreshErr != nil {
					failure("the webhook source policy could not update its service IP union")
					if ctx.Err() != nil || errors.Is(refreshErr, errIntegrationIntent) {
						return "", refreshErr
					}
				}
			}
			return revision, err
		},
		Report: func(ready bool, err error) {
			if err != nil {
				failure("the stable webhook publisher could not become ready")
			} else if ready {
				reportIntegrationURL(tunnel, output, "webhooks ready", "", clioutput.Fields(clioutput.Field{Label: "webhook origin", Value: origin.URL}))
			}
		},
	}
}
