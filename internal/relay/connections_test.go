package relay

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/relayv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestRegistryCandidateRequiresExactCurrentPublisherConnection(t *testing.T) {
	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	connection := &PublisherConnection{
		ref: tunnelv1.PublisherConnectionRef{
			RouteID: "route_1", RouteSessionID: "route_session_1", RouteVersion: 2,
			PublisherConnectionID: "publisher_connection_1", ConnectionSlot: 0,
			ConnectionAssignmentRevision: 3, RelayServiceID: "relay_service_1",
		},
		claimed: relayv1.ClaimedPublisherConnection{
			RelayId: "relay_1", RelayRunId: "relay_run_1", RelayLeaseRevision: 4,
		},
	}
	registry := &Registry{connections: map[string]*PublisherConnection{
		connection.ref.PublisherConnectionID: connection,
	}}
	header := tunnelv1.InternalForwardingHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.InternalForwardingStream,
		VisitorConnectionID: "visitor_connection_1", RouteID: "route_1",
		RouteSessionID: "route_session_1", RouteVersion: 2,
		PublisherConnectionID: "publisher_connection_1", ConnectionSlot: 0,
		ConnectionAssignmentRevision: 3,
		RelayServiceID:               "relay_service_1", RelayID: "relay_1",
		RelayRunID: "relay_run_1", RelayLeaseRevision: 4,
		RouteExpiresAt: now.Add(time.Minute), LeaseExpiresAt: now.Add(time.Minute),
	}
	if candidate, ok := registry.Candidate(header, now); !ok || candidate != connection {
		t.Fatal("exact current publisher connection was not selected")
	}

	tests := map[string]func(*tunnelv1.InternalForwardingHeader){
		"route ID":                       func(value *tunnelv1.InternalForwardingHeader) { value.RouteID = "route_2" },
		"route session ID":               func(value *tunnelv1.InternalForwardingHeader) { value.RouteSessionID = "route_session_2" },
		"route version":                  func(value *tunnelv1.InternalForwardingHeader) { value.RouteVersion++ },
		"publisher connection ID":        func(value *tunnelv1.InternalForwardingHeader) { value.PublisherConnectionID = "publisher_connection_2" },
		"connection slot":                func(value *tunnelv1.InternalForwardingHeader) { value.ConnectionSlot = 1 },
		"connection assignment revision": func(value *tunnelv1.InternalForwardingHeader) { value.ConnectionAssignmentRevision++ },
		"relay service ID":               func(value *tunnelv1.InternalForwardingHeader) { value.RelayServiceID = "relay_service_2" },
		"relay ID":                       func(value *tunnelv1.InternalForwardingHeader) { value.RelayID = "relay_2" },
		"relay process run ID":           func(value *tunnelv1.InternalForwardingHeader) { value.RelayRunID = "relay_run_2" },
		"relay lease revision":           func(value *tunnelv1.InternalForwardingHeader) { value.RelayLeaseRevision++ },
		"expired route":                  func(value *tunnelv1.InternalForwardingHeader) { value.RouteExpiresAt = now },
		"expired relay lease":            func(value *tunnelv1.InternalForwardingHeader) { value.LeaseExpiresAt = now },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			stale := header
			mutate(&stale)
			if candidate, ok := registry.Candidate(stale, now); ok || candidate != nil {
				t.Fatalf("Candidate returned %#v, %t; want stale-state rejection", candidate, ok)
			}
		})
	}
}
