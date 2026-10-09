package main

import (
	"encoding/json"
	"time"

	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/webhookips"
)

type telemetryEventID string
type telemetryWireEventName string

const (
	wireCommandStarted     telemetryWireEventName = "command.started"
	wireCommandCompleted   telemetryWireEventName = "command.completed"
	wireCommandFailed      telemetryWireEventName = "command.failed"
	wireTunnelReady        telemetryWireEventName = "tunnel.ready"
	wireDemoFirstPing      telemetryWireEventName = "demo.first_ping"
	wireOAuthReady         telemetryWireEventName = "oauth.callback_url.ready"
	wireOAuthRedirected    telemetryWireEventName = "oauth.callback.redirected"
	wireWebhookReady       telemetryWireEventName = "webhook.endpoint.ready"
	wireWebhookReached     telemetryWireEventName = "webhook.delivery.reached_receiver"
	wireProviderConfigured telemetryWireEventName = "webhook.provider.configured"
	wireProviderReady      telemetryWireEventName = "webhook.provider.ready"
	wireProviderReached    telemetryWireEventName = "webhook.provider.reached_receiver"
)

type telemetryEventCommon struct {
	EventID      telemetryEventID `json:"event_id"`
	InvocationID string           `json:"invocation_id"`
	OccurredAt   time.Time        `json:"occurred_at"`
	EventVersion int              `json:"event_version"`
}

type telemetryWireEvent interface{ isTelemetryWireEvent() }

type telemetryCommandWirePayload struct {
	Command telemetryTrackedCommand `json:"command"`
	Action  telemetryCommandAction  `json:"action,omitempty"`
}

type telemetryFailureWirePayload struct {
	Command        telemetryTrackedCommand `json:"command"`
	Action         telemetryCommandAction  `json:"action,omitempty"`
	FailureStage   telemetryFailureStage   `json:"failure_stage"`
	DiagnosticCode diagnostic.Code         `json:"diagnostic_code,omitempty"`
}

type telemetryTunnelWirePayload struct {
	Source      telemetryTrackedCommand `json:"source"`
	ServerKind  telemetryServerKind     `json:"server_kind"`
	Framework   telemetryFrameworkName  `json:"framework,omitempty"`
	PublishMode telemetryPublishMode    `json:"publish_mode,omitempty"`
}

type telemetryDemoWirePayload struct {
	PublishMode telemetryPublishMode `json:"publish_mode"`
}

type telemetryWebhookWirePayload struct {
	Delivery telemetryWebhookDelivery `json:"delivery"`
}

type telemetryProviderWirePayload struct {
	Provider string `json:"provider"`
}

type telemetryCommandWireEvent struct {
	telemetryEventCommon
	Name    telemetryWireEventName      `json:"name"`
	Payload telemetryCommandWirePayload `json:"payload"`
}

type telemetryFailureWireEvent struct {
	telemetryEventCommon
	Name    telemetryWireEventName      `json:"name"`
	Payload telemetryFailureWirePayload `json:"payload"`
}

type telemetryTunnelWireEvent struct {
	telemetryEventCommon
	Name    telemetryWireEventName     `json:"name"`
	Payload telemetryTunnelWirePayload `json:"payload"`
}

type telemetryDemoWireEvent struct {
	telemetryEventCommon
	Name    telemetryWireEventName   `json:"name"`
	Payload telemetryDemoWirePayload `json:"payload"`
}

type telemetryOAuthWireEvent struct {
	telemetryEventCommon
	Name    telemetryWireEventName `json:"name"`
	Payload struct{}               `json:"payload"`
}

type telemetryWebhookWireEvent struct {
	telemetryEventCommon
	Name    telemetryWireEventName      `json:"name"`
	Payload telemetryWebhookWirePayload `json:"payload"`
}

type telemetryProviderWireEvent struct {
	telemetryEventCommon
	Name    telemetryWireEventName       `json:"name"`
	Payload telemetryProviderWirePayload `json:"payload"`
}

func (telemetryCommandWireEvent) isTelemetryWireEvent()  {}
func (telemetryFailureWireEvent) isTelemetryWireEvent()  {}
func (telemetryTunnelWireEvent) isTelemetryWireEvent()   {}
func (telemetryDemoWireEvent) isTelemetryWireEvent()     {}
func (telemetryOAuthWireEvent) isTelemetryWireEvent()    {}
func (telemetryWebhookWireEvent) isTelemetryWireEvent()  {}
func (telemetryProviderWireEvent) isTelemetryWireEvent() {}

func (payload telemetryPayload) wireEvent(id telemetryEventID) telemetryWireEvent {
	common := telemetryEventCommon{EventID: id, InvocationID: payload.InvocationID, OccurredAt: time.Now().UTC(), EventVersion: 1}
	switch payload.Event {
	case telemetryCommandStarted:
		return telemetryCommandWireEvent{common, wireCommandStarted, telemetryCommandWirePayload{payload.Command, payload.Action}}
	case telemetryCommandCompleted:
		return telemetryCommandWireEvent{common, wireCommandCompleted, telemetryCommandWirePayload{payload.Command, payload.Action}}
	case telemetryCommandFailed:
		return telemetryFailureWireEvent{common, wireCommandFailed, telemetryFailureWirePayload{payload.Command, payload.Action, payload.FailureStage, payload.DiagnosticCode}}
	case telemetryPublishRunStarted:
		return telemetryTunnelWireEvent{common, wireTunnelReady, telemetryTunnelWirePayload{payload.Command, payload.ServerKind, payload.Framework, payload.PublishMode}}
	case telemetryDemoPingReceived:
		return telemetryDemoWireEvent{common, wireDemoFirstPing, telemetryDemoWirePayload{telemetryPublishDemo}}
	case telemetryOAuthReady:
		return telemetryOAuthWireEvent{telemetryEventCommon: common, Name: wireOAuthReady}
	case telemetryOAuthRedirected:
		return telemetryOAuthWireEvent{telemetryEventCommon: common, Name: wireOAuthRedirected}
	case telemetryWebhookReady:
		return telemetryWebhookWireEvent{common, wireWebhookReady, telemetryWebhookWirePayload{payload.Delivery}}
	case telemetryWebhookReached:
		return telemetryWebhookWireEvent{common, wireWebhookReached, telemetryWebhookWirePayload{payload.Delivery}}
	case telemetryProviderConfigured, telemetryProviderReady, telemetryProviderReached:
		if !webhookips.Valid(payload.Provider) {
			return nil
		}
		name := wireProviderConfigured
		if payload.Event == telemetryProviderReady {
			name = wireProviderReady
		} else if payload.Event == telemetryProviderReached {
			name = wireProviderReached
		}
		return telemetryProviderWireEvent{common, name, telemetryProviderWirePayload{payload.Provider}}
	default:
		return nil
	}
}

type telemetryClientMetadata struct {
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	CI      bool   `json:"ci"`
}

type telemetryBatch struct {
	SchemaVersion  int                     `json:"schema_version"`
	InstallationID string                  `json:"installation_id"`
	Client         telemetryClientMetadata `json:"client"`
	Events         []json.RawMessage       `json:"events"`
}
