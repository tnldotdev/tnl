// package telemetry owns bounded collection, queueing, and delivery for native
// CLI and publisher telemetry. it depends on client state and the authored API;
// commands and runtimes supply observations without transferring their lifetime.
package telemetry

import (
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

type EventKind uint8

const (
	CommandCompleted EventKind = iota + 1
	CommandFailed
	CommandCanceled
	PublicationReady
	DemoFirstPing
	OAuthReady
	OAuthRedirected
	WebhookReady
	WebhookReached
)

// Observation contains semantic facts only. wire models, bounds, and allowed
// field names come from the generated v1 contract.
type Observation struct {
	Event        EventKind
	Command      api.CommandOutcomeCommand
	Action       api.CommandOutcomeAction
	FailureStage api.CommandOutcomeFailureStage
	ServerKind   api.PublicationReadyServerKind
	PublishMode  api.PublicationReadyPublishMode
	Framework    api.PublicationReadyFramework
	Delivery     api.IntegrationOutcomeDelivery
}

type Reporter interface{ Report(Observation) }

func (o Observation) wire(id string) (api.Event, error) {
	var event api.Event
	switch o.Event {
	case CommandCompleted, CommandFailed, CommandCanceled:
		command := o.Command
		if !command.Valid() {
			command = api.CommandOutcomeCommandOther
		}
		payload := api.CommandOutcome{Command: command, Outcome: api.Completed}
		if o.Event == CommandFailed {
			payload.Outcome = api.Failed
		} else if o.Event == CommandCanceled {
			payload.Outcome = api.Canceled
		}
		if o.Action != "" {
			action := o.Action
			if !action.Valid() {
				action = api.CommandOutcomeActionOther
			}
			payload.Action = &action
		}
		if o.Event == CommandFailed && o.FailureStage.Valid() {
			payload.FailureStage = &o.FailureStage
		}
		err := event.FromCommandEvent(api.CommandEvent{EventId: id, EventVersion: api.V1, Name: api.CommandEventNameCommandOutcome, Payload: payload})
		return event, err
	case PublicationReady:
		mode := o.PublishMode
		if !mode.Valid() {
			mode = api.App
		}
		payload := api.PublicationReady{ServerKind: o.ServerKind, PublishMode: mode}
		if o.Framework.Valid() {
			payload.Framework = &o.Framework
		}
		err := event.FromReadyEvent(api.ReadyEvent{EventId: id, EventVersion: api.V1, Name: api.TunnelReady, Payload: payload})
		return event, err
	case DemoFirstPing:
		err := event.FromDemoEvent(api.DemoEvent{EventId: id, EventVersion: api.V1, Name: api.DemoFirstPing, Payload: map[string]any{}})
		return event, err
	case OAuthReady, OAuthRedirected, WebhookReady, WebhookReached:
		payload := api.IntegrationOutcome{Kind: api.Oauth, Outcome: api.Ready}
		if o.Event == OAuthRedirected {
			payload.Outcome = api.Redirected
		}
		if o.Event == WebhookReady || o.Event == WebhookReached {
			payload.Kind = api.Webhook
			if o.Event == WebhookReached {
				payload.Outcome = api.ReachedReceiver
			}
			if o.Delivery.Valid() {
				payload.Delivery = &o.Delivery
			}
		}
		err := event.FromIntegrationEvent(api.IntegrationEvent{EventId: id, EventVersion: api.V1, Name: api.IntegrationEventNameIntegrationOutcome, Payload: payload})
		return event, err
	default:
		return event, api.ErrInvalid
	}
}
