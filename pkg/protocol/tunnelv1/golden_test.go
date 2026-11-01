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
		PublisherConnection: &PublisherConnectionRef{
			PublishRunID: "publish_run_1", PublicURLID: "public_url_1", PublishRunNumber: 2,
			PublisherConnectionID: "publisher_connection_1", ConnectionSlot: 1,
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
	connectorRenew := connectorHello
	connectorRenew.Type, connectorRenew.RequestID = ConnectorLegRenew, "renew_1"
	assertGoldenFrame(t, "control-connector-renew", connectorRenew, WriteControl, ReadControl)
	connectorAccepted := Message{Type: HelloAccepted, ProtocolVersion: Version,
		ConnectorPairLegAccepted: &ConnectorPairLegAccepted{PairID: "cpp_1234567890123456789012", DeliveryID: "AQEBAQEBAQEBAQEBAQEBAQ",
			DeliveryGeneration: 3, ConnectionSlot: 1, SourceIP: "192.0.2.10",
			ObservedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			ExpiresAt:  time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC)}}
	assertGoldenFrame(t, "control-connector-accepted", connectorAccepted, WriteControl, ReadControl)
	connectorRenewed := connectorAccepted
	connectorRenewed.Type, connectorRenewed.RequestID = ConnectorLegRenewed, "renew_1"
	assertGoldenFrame(t, "control-connector-renewed", connectorRenewed, WriteControl, ReadControl)
	assertGoldenFrame(t, "control-accepted", Message{Type: HelloAccepted, ProtocolVersion: Version}, WriteControl, ReadControl)
	assertGoldenFrame(t, "connector-peer-visitor-entry", peerOpeningFixture(), WriteConnectorPeerVisitorEntry, ReadConnectorPeerVisitorEntry)
	assertGoldenFrame(t, "visitor-stream-header", VisitorStreamHeader{
		ProtocolVersion: Version, Kind: VisitorStream, VisitorConnectionID: "visitor_connection_1",
		PublicURLID: "public_url_1", PublishRunID: "publish_run_1", PublishRunNumber: 2,
		PublisherConnectionID: "publisher_connection_1", ConnectionAssignmentRevision: 3,
	}, WriteVisitorStreamHeader, ReadVisitorStreamHeader)
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	assertGoldenFrame(t, "internal-forwarding-header", InternalForwardingHeader{
		ProtocolVersion: Version, Kind: InternalForwardingStream, VisitorConnectionID: "visitor_connection_1",
		PublicURLID: "public_url_1", PublishRunID: "publish_run_1", PublishRunNumber: 2,
		PublisherConnectionID: "publisher_connection_1", ConnectionSlot: 1,
		ConnectionAssignmentRevision: 3, RelayServiceID: "relay_service_1", RelayID: "relay_1",
		RelayRunID: "relay_run_1", RelayLeaseRevision: 4,
		PublicUrlExpiresAt: now.Add(time.Hour), LeaseExpiresAt: now.Add(time.Minute),
	}, WriteInternalForwardingHeader, ReadInternalForwardingHeader)
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
		{"invalid-visitor-missing-field", readVisitor},
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
		t.Fatalf("JSON = %s; want %s", encoded, compactJSON.Bytes())
	}
	// the JSON and hex files are independent, committed expectations.
	wantWire := goldenWire(t, name)
	var wire bytes.Buffer
	if err := write(&wire, want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire.Bytes(), wantWire) {
		t.Fatalf("framed wire = %x; want %x", wire.Bytes(), wantWire)
	}
	got, err := read(bytes.NewReader(wantWire))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded fixture = %#v; want %#v", got, want)
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
