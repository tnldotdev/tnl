// package telemetry owns optional native client collection and delivery. commands
// and publication owners supply generated contract values; transports only update
// bounded memory through callbacks. no server runtime depends on this owner.
package telemetry

import (
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

func eventID() string { id, _ := opaqueid.New(opaqueid.TelemetryEventPrefix); return id }

// event constructors use generated payloads directly. validation remains at the
// queue and receiver boundaries, rather than maintaining another payload model.
func Command(payload api.CommandOutcome) api.Event {
	id, _ := opaqueid.New(opaqueid.TelemetryEventPrefix)
	var event api.Event
	_ = event.FromCommandEvent(api.CommandEvent{EventId: id, EventVersion: 1, Name: "command.outcome", Payload: payload})
	return event
}

func Ready(payload api.PublicationReady) api.Event {
	id, _ := opaqueid.New(opaqueid.TelemetryEventPrefix)
	var event api.Event
	_ = event.FromReadyEvent(api.ReadyEvent{EventId: id, EventVersion: 1, Name: "tunnel.ready", Payload: payload})
	return event
}

func Integration(payload api.IntegrationOutcome) api.Event {
	id, _ := opaqueid.New(opaqueid.TelemetryEventPrefix)
	var event api.Event
	_ = event.FromIntegrationEvent(api.IntegrationEvent{EventId: id, EventVersion: 1, Name: "integration.outcome", Payload: payload})
	return event
}

func Demo() api.Event {
	id, _ := opaqueid.New(opaqueid.TelemetryEventPrefix)
	var event api.Event
	_ = event.FromDemoEvent(api.DemoEvent{EventId: id, EventVersion: 1, Name: "demo.first_ping", Payload: map[string]any{}})
	return event
}
