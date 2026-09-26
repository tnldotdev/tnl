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
	assertGoldenFrame(t, "stream-response", StreamResponse{
		Type: StreamRejected, Code: StaleConnectionAssignment,
	}, WriteStreamResponse, ReadStreamResponse)
}

func TestInvalidFixtures(t *testing.T) {
	for _, test := range []struct {
		name string
		read func(io.Reader) error
	}{
		{"invalid-control-unknown-field", readControl},
		{"invalid-visitor-missing-field", readVisitor},
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
	// The JSON and hex files are independent, committed expectations.
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
