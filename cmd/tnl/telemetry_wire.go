package main

import (
	"encoding/json"
	"time"

	"github.com/tnldotdev/tnl/internal/diagnostic"
)

type telemetryEventID string
type telemetryWireEventName string

const (
	wireCommandStarted   telemetryWireEventName = "command.started"
	wireCommandCompleted telemetryWireEventName = "command.completed"
	wireCommandFailed    telemetryWireEventName = "command.failed"
	wireTunnelReady      telemetryWireEventName = "tunnel.ready"
	wireDemoFirstPing    telemetryWireEventName = "demo.first_ping"
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
}

type telemetryFailureWirePayload struct {
	Command        telemetryTrackedCommand `json:"command"`
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

func (telemetryCommandWireEvent) isTelemetryWireEvent() {}
func (telemetryFailureWireEvent) isTelemetryWireEvent() {}
func (telemetryTunnelWireEvent) isTelemetryWireEvent()  {}
func (telemetryDemoWireEvent) isTelemetryWireEvent()    {}

func (payload telemetryPayload) wireEvent(id telemetryEventID) telemetryWireEvent {
	common := telemetryEventCommon{EventID: id, InvocationID: payload.InvocationID, OccurredAt: time.Now().UTC(), EventVersion: 1}
	switch payload.Event {
	case telemetryCommandStarted:
		return telemetryCommandWireEvent{common, wireCommandStarted, telemetryCommandWirePayload{payload.Command}}
	case telemetryCommandCompleted:
		return telemetryCommandWireEvent{common, wireCommandCompleted, telemetryCommandWirePayload{payload.Command}}
	case telemetryCommandFailed:
		return telemetryFailureWireEvent{common, wireCommandFailed, telemetryFailureWirePayload{payload.Command, payload.FailureStage, payload.DiagnosticCode}}
	case telemetryPublishRunStarted:
		return telemetryTunnelWireEvent{common, wireTunnelReady, telemetryTunnelWirePayload{payload.Command, payload.ServerKind, payload.Framework, payload.PublishMode}}
	case telemetryDemoPingReceived:
		return telemetryDemoWireEvent{common, wireDemoFirstPing, telemetryDemoWirePayload{telemetryPublishDemo}}
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
