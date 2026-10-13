package main

import (
	"context"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/projectmeta"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func reportIntegrationURL(tunnel *clientstate.Tunnel, output *publishOutput, state, footer string, blocks ...clioutput.Block) {
	localpublisher.ReportIntegration(tunnel, output.integrationURLMessage, state, footer, blocks...)
}

func projectIntegrationGroup(project projectconfig.Project, namespace string) string {
	return localpublisher.IntegrationGroup(project, namespace)
}
func projectOAuthPublisher(ctx context.Context, state *clientstate.Database, project projectconfig.Project, server, team string, auth *clientauth.Client) (projectmeta.IntegrationOrigin, publisherServices, error) {
	origin, services, err := localpublisher.OAuthServices(ctx, state, project, server, team, auth)
	return origin, servicesFromLocal(services), err
}
func integrationURLConfig(services publisherServices, hostname string, purpose controlv1.PublicURLPurpose) publisher.Config {
	return localpublisher.IntegrationConfig(services.local(), hostname, purpose)
}

type integrationTelemetryAdapter struct{ reporter telemetryReporter }

func (a integrationTelemetryAdapter) Report(event localpublisher.IntegrationEvent) {
	a.reporter.Report(newIntegrationTelemetry(telemetryEventName(event.Name), telemetryWebhookDelivery(event.Delivery)))
}
func integrationReporter(reporter telemetryReporter) localpublisher.IntegrationReporter {
	if reporter == nil {
		return nil
	}
	return integrationTelemetryAdapter{reporter}
}
func startOAuthIntegrationURL(ctx context.Context, state *clientstate.Database, services publisherServices, origin projectmeta.IntegrationOrigin, tunnel *clientstate.Tunnel, output *publishOutput, reporter telemetryReporter) func() {
	return localpublisher.StartOAuth(ctx, state, services.local(), origin, tunnel, output.integrationURLMessage, integrationReporter(reporter))
}
func startWebhookIntegrationURL(ctx context.Context, state *clientstate.Database, services publisherServices, project projectconfig.Project, tunnel *clientstate.Tunnel, service, group string, output *publishOutput, reporter telemetryReporter) func() {
	return localpublisher.StartWebhooks(ctx, state, services.local(), project, tunnel, service, group, output.integrationURLMessage, integrationReporter(reporter))
}
func readyWebhookDelivery(ctx context.Context, state *clientstate.Database, server, group, hostname string, definitions map[string]config.Webhook) telemetryWebhookDelivery {
	return telemetryWebhookDelivery(localpublisher.ReadyWebhookDelivery(ctx, state, server, group, hostname, definitions))
}
