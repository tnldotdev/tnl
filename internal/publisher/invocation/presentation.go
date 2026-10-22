package invocation

import (
	"context"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/demo"
)

// Progress carries semantic content; the command owns framing and its terminal.
type Progress struct {
	State   string
	Hint    string
	Details []clioutput.Block
}

type IntegrationObservation struct {
	Event    string
	Delivery string
}

type Presentation struct {
	Delegated        func()
	ConfigureBrowser func(bool)
	Demo             func()
	GuestDemo        func()
	GuestShare       func(string)
	DemoPing         func(demo.State) error
	Logf             func(string, ...any)
	PublisherEvent   func(context.Context, *clientstate.Tunnel, string, publisher.Event) error
	Starting         func(string, string) error
	Provisioning     func(string, uint64) error
	Ready            func(string, uint64) error
	Stopped          func() error
	Progress         func(Progress) error
	Warning          func(string) error
	Observe          func(IntegrationObservation)
}

func (p *Presentation) configureBrowser(automated bool) {
	if p != nil && p.ConfigureBrowser != nil {
		p.ConfigureBrowser(automated)
	}
}
func (p *Presentation) setDemo() {
	if p != nil && p.Demo != nil {
		p.Demo()
	}
}
func (p *Presentation) setGuestDemo() {
	if p != nil && p.GuestDemo != nil {
		p.GuestDemo()
	}
}
func (p *Presentation) setGuestShare(secret string) {
	if p != nil && p.GuestShare != nil {
		p.GuestShare(secret)
	}
}
func (p *Presentation) publisherEvent(ctx context.Context, tunnel *clientstate.Tunnel, server string, event publisher.Event) error {
	if p == nil || p.PublisherEvent == nil {
		return nil
	}
	return p.PublisherEvent(ctx, tunnel, server, event)
}

func (p *Presentation) starting(id, target string) error {
	if p == nil || p.Starting == nil {
		return nil
	}
	return p.Starting(id, target)
}
func (p *Presentation) provisioning(url string, run uint64) error {
	if p == nil || p.Provisioning == nil {
		return nil
	}
	return p.Provisioning(url, run)
}
func (p *Presentation) ready(url string, run uint64) error {
	if p == nil || p.Ready == nil {
		return nil
	}
	return p.Ready(url, run)
}
func (p *Presentation) stopped() error {
	if p == nil || p.Stopped == nil {
		return nil
	}
	return p.Stopped()
}

func (p *Presentation) integrationURLMessage(state, hint string, details ...clioutput.Block) error {
	if p == nil || p.Progress == nil {
		return nil
	}
	return p.Progress(Progress{State: state, Hint: hint, Details: details})
}

func publishWarning(tunnel *clientstate.Tunnel, output *Presentation) func(string) {
	return func(message string) {
		if output == nil || output.Warning == nil {
			return
		}
		if err := output.Warning(message); err != nil {
			tunnel.CancelWithCause(failure.Wrap("write publication warning", failure.OutputUnavailable, err))
		}
	}
}

type telemetryWebhookDelivery string
type telemetryEventName string

const (
	telemetryFanout          telemetryWebhookDelivery = "fanout"
	telemetrySelected        telemetryWebhookDelivery = "selected"
	telemetryOAuthReady      telemetryEventName       = "oauth_callback_url_ready"
	telemetryOAuthRedirected telemetryEventName       = "oauth_callback_redirected"
	telemetryWebhookReady    telemetryEventName       = "webhook_endpoint_ready"
	telemetryWebhookReached  telemetryEventName       = "webhook_delivery_reached_receiver"
)

type telemetryReporter func(IntegrationObservation)

func (r telemetryReporter) Report(value IntegrationObservation) {
	if r != nil {
		r(value)
	}
}
func newIntegrationTelemetry(event telemetryEventName, delivery telemetryWebhookDelivery) IntegrationObservation {
	return IntegrationObservation{Event: string(event), Delivery: string(delivery)}
}

func failureMessage(err error) string {
	_, message, ok := failure.Describe(err)
	if ok {
		return message.Message
	}
	return err.Error()
}
