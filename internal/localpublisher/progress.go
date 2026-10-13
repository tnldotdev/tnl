package localpublisher

import (
	"context"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/publisher"
)

// progress carries semantic details to the caller's output adapter.
type Progress func(state, footer string, blocks ...clioutput.Block) error

type publishOutput struct{ progress Progress }

func (o *publishOutput) integrationURLMessage(state, footer string, blocks ...clioutput.Block) error {
	if o.progress == nil {
		return nil
	}
	return o.progress(state, footer, blocks...)
}

type IntegrationEvent struct{ Name, Delivery string }
type IntegrationReporter interface{ Report(IntegrationEvent) }
type telemetryReporter = IntegrationReporter
type telemetryWebhookDelivery = string

const (
	telemetryOAuthReady      = "oauth_callback_url_ready"
	telemetryOAuthRedirected = "oauth_callback_redirected"
	telemetryWebhookReady    = "webhook_endpoint_ready"
	telemetryWebhookReached  = "webhook_delivery_reached_receiver"
	telemetryFanout          = "fanout"
	telemetrySelected        = "selected"
)

func newIntegrationTelemetry(name, delivery string) IntegrationEvent {
	return IntegrationEvent{Name: name, Delivery: delivery}
}

func RecordPublisherEvent(ctx context.Context, tunnel *clientstate.Tunnel, event publisher.Event) error {
	switch event.Type {
	case publisher.EventPublicURLAssigned:
		return tunnel.SetPublicURL(ctx, event.PublicURLID, event.Hostname)
	case publisher.EventProvisioning:
		return tunnel.SetProvisioning(ctx, event.PublishRunNumber)
	case publisher.EventReady:
		return tunnel.SetReady(ctx, event.PublicURL, event.PublishRunNumber)
	case publisher.EventDraining:
		return tunnel.SetDraining(context.WithoutCancel(ctx))
	}
	return nil
}
