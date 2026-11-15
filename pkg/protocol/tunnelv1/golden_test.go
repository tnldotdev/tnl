package tunnelv1

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestGoldenJSONAndFramedWireFixtures(t *testing.T) {
	assertGoldenFrame(t, "control-hello", Message{
		Type: Hello, ProtocolVersion: Version, Role: Publisher, Credential: "credential",
		ServiceConnection: &ServicePublisherConnectionRef{
			ServiceID: "svc_1234567890123456789012", ServiceRunID: "srun_1234567890123456789012", RunNumber: 2,
			PublisherConnectionID: "pc_1234567890123456789012", ConnectionSlot: 1,
			ConnectionAssignmentRevision: 3, RelayServiceID: "relay_service_1",
		},
	}, WriteControl, ReadControl)
	connectorHello := Message{
		Type: Hello, ProtocolVersion: Version, Role: Connector,
		ConnectorPairLegProof: &ConnectorPairLegProof{PairID: "cpp_1234567890123456789012", DeliveryGeneration: 3,
			ServiceID: "svc_1234567890123456789012", ServiceRunID: "srun_1234567890123456789012", RunNumber: 2,
			PublisherIdentityID: "pub_1234567890123456789012", ConnectionSlot: 0,
			PublisherConnectionID: "pc_1234567890123456789012", AssignmentRevision: 5,
			RelayServiceID: "relay-a", RelayID: "node-a", RelayRunID: "process-a", RelayLeaseRevision: 3,
			RequestedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Nonce: make([]byte, 32), Signature: make([]byte, 64)},
	}
	assertGoldenFrame(t, "control-connector-hello", connectorHello, WriteControl, ReadControl)
	connectorActivate := Message{Type: ConnectorLegActivate, ProtocolVersion: Version, RequestID: "activate_1", Role: Connector,
		ConnectorLegBinding: &ConnectorLegBinding{Nonce: make([]byte, 32)}}
	assertGoldenFrame(t, "control-connector-activate", connectorActivate, WriteControl, ReadControl)
	connectorActivate.Type, connectorActivate.Role = ConnectorLegActivated, ""
	assertGoldenFrame(t, "control-connector-activated", connectorActivate, WriteControl, ReadControl)
	handoff, err := NewConnectorHandoff(ConnectorHandoffID(bytes.Repeat([]byte{2}, 32)), ConnectorHandoffID(bytes.Repeat([]byte{3}, 32)), 7)
	if err != nil {
		t.Fatal(err)
	}
	replacement := InitialConnectorActivation(ConnectorHelloNonce(bytes.Repeat([]byte{1}, 32))).Replacing(handoff).Binding()
	connectorReplace := Message{Type: ConnectorLegActivate, ProtocolVersion: Version, RequestID: "repair", Role: Connector, ConnectorLegBinding: &replacement}
	assertGoldenFrame(t, "control-connector-replace", connectorReplace, WriteControl, ReadControl)
	connectorReplace.Type, connectorReplace.Role = ConnectorLegActivated, ""
	assertGoldenFrame(t, "control-connector-replaced", connectorReplace, WriteControl, ReadControl)
	connectorRenew := connectorHello
	connectorRenew.Type, connectorRenew.RequestID = ConnectorLegRenew, "renew_1"
	assertGoldenFrame(t, "control-connector-renew", connectorRenew, WriteControl, ReadControl)
	connectorAccepted := Message{Type: HelloAccepted, ProtocolVersion: Version,
		ConnectorPairLegAccepted: &ConnectorPairLegAccepted{PairID: "cpp_1234567890123456789012", DeliveryID: "AQEBAQEBAQEBAQEBAQEBAQ",
			DeliveryGeneration: 3, BindingState: ConnectorPeerLegBindingActive, ConnectionSlot: 1, SourceIP: "192.0.2.10",
			ObservedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			ExpiresAt:  time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC)}}
	assertGoldenFrame(t, "control-connector-accepted", connectorAccepted, WriteControl, ReadControl)
	connectorRenewed := connectorAccepted
	connectorRenewed.Type, connectorRenewed.RequestID = ConnectorLegRenewed, "renew_1"
	assertGoldenFrame(t, "control-connector-renewed", connectorRenewed, WriteControl, ReadControl)
	assertGoldenFrame(t, "control-accepted", Message{Type: HelloAccepted, ProtocolVersion: Version}, WriteControl, ReadControl)
	assertGoldenFrame(t, "connector-peer-visitor-entry", peerOpeningFixture(), WriteConnectorPeerVisitorEntry, ReadConnectorPeerVisitorEntry)
	assertGoldenFrame(t, "connector-peer-connectivity", connectorPeerConnectivityFixture(), WriteConnectorPeerConnectivity, ReadConnectorPeerConnectivity)
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	forwarding := ServiceForwardingHeader{
		ServiceStreamHeader: ServiceStreamHeader{
			ProtocolVersion: Version, Kind: ServiceForwardingStream,
			ServiceID: "svc_1234567890123456789012", ServiceRunID: "srun_1234567890123456789012",
			PublicService: &PublicServiceAdmission{IngressID: "ingress_1", IngressRunID: "ir_1234567890123456789012", IngressLeaseRevision: 4, DestinationPort: 443},
			SourceIP:      "192.0.2.1", RunNumber: 2, VisitorConnectionID: "vc_1234567890123456789012",
			PublisherConnectionID: "pc_1234567890123456789012", ConnectionAssignmentRevision: 3,
			ExpiresAt: now.Add(time.Hour),
		},
		ConnectionSlot: 1, RelayServiceID: "relay_service_1", RelayID: "relay_1",
		RelayRunID: "rr_1234567890123456789012", RelayLeaseRevision: 4, LeaseExpiresAt: now.Add(time.Minute),
	}
	assertGoldenFrame(t, "service-forwarding-header", forwarding, WriteServiceForwardingHeader, ReadServiceForwardingHeader)
	assertGoldenFrame(t, "service-capacity", ServiceCapacityRequest{
		Kind: "service_capacity", Stream: forwarding, Deadline: now.Add(5 * time.Second),
	}, WriteServiceCapacityRequest, ReadServiceCapacityRequest)
}

func TestInvalidFixtures(t *testing.T) {
	for _, test := range []struct {
		name string
		read func(io.Reader) error
	}{
		{"invalid-control-unknown-field", readControl},
		{"invalid-connector-publisher-role", readControl},
		{"invalid-connector-credential", readControl},
		{"invalid-connector-missing-proof", readControl},
		{"invalid-connector-receipt-on-hello", readControl},
		{"invalid-connector-receipt-on-ping", readControl},
		{"invalid-connector-receipt-source", readControl},
		{"invalid-connector-activation-null", readControl},
		{"invalid-connector-activation-foreign-field", readControl},
		{"invalid-connector-replacement-missing-revision", readControl},
		{"invalid-connector-replacement-revision-overflow", readControl},
		{"invalid-legacy-publisher-hello", readControl},
		{"invalid-legacy-service-stream", readServiceForwarding},
		{"invalid-connector-peer-unknown-field", readConnectorPeerVisitor},
		{"invalid-connector-peer-missing-field", readConnectorPeerVisitor},
		{"invalid-connector-peer-wrong-subject", readConnectorPeerVisitor},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.read(frame(string(readFixture(t, test.name+".json")))); err == nil {
				t.Fatal("invalid fixture was accepted")
			}
		})
	}
}

func assertGoldenFrame[T any](t *testing.T, name string, want T, write func(io.Writer, T) error, read func(io.Reader) (T, error)) {
	t.Helper()
	var compactJSON bytes.Buffer
	if err := json.Compact(&compactJSON, readFixture(t, name+".json")); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, compactJSON.Bytes()) {
		t.Fatalf("JSON does not match %s.json", name)
	}
	fromJSON, err := read(frame(compactJSON.String()))
	if err != nil {
		t.Fatalf("could not read %s.json with its frame parser", name)
	}
	if !reflect.DeepEqual(fromJSON, want) {
		t.Fatalf("decoded %s.json does not match the expected message", name)
	}
	// the JSON and hex files are independent, committed expectations.
	wantWire := goldenWire(t, name)
	var wire bytes.Buffer
	if err := write(&wire, want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire.Bytes(), wantWire) {
		t.Fatalf("framed wire does not match %s.frame.hex", name)
	}
	got, err := read(bytes.NewReader(wantWire))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded %s.frame.hex does not match the expected message", name)
	}
}

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
