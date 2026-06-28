package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestControlFramesAreStrictAndBounded(t *testing.T) {
	connection := &PublisherConnectionRef{
		RouteSessionID: "route_session_1", RouteID: "route_1", RouteVersion: 2,
		PublisherConnectionID: "publisher_connection_1", ConnectionSlot: 1,
		ConnectionAssignmentRevision: 3, RelayServiceID: "relay_service_1",
	}
	valid := []Message{
		{Type: Hello, ProtocolVersion: Version, Role: Publisher, Credential: "secret", PublisherConnection: connection},
		{Type: Hello, ProtocolVersion: Version, Role: Ingress, Credential: "cluster-secret"},
		{Type: HelloAccepted, ProtocolVersion: Version},
		{Type: Ping, ProtocolVersion: Version, RequestID: "request_1"},
		{Type: Pong, ProtocolVersion: Version, RequestID: "request_1"},
		{Type: Drain, ProtocolVersion: Version, RequestID: "request_2"},
		{Type: Draining, ProtocolVersion: Version, RequestID: "request_2"},
		{Type: Drained, ProtocolVersion: Version, RequestID: "request_2"},
		{Type: GoAway, ProtocolVersion: Version, Code: DrainingPublisherConnection},
		{Type: Error, ProtocolVersion: Version, RequestID: "request_3", Code: StaleConnectionAssignment},
	}
	for _, message := range valid {
		var wire bytes.Buffer
		if err := WriteControl(&wire, message); err != nil {
			t.Fatalf("WriteControl(%s): %v", message.Type, err)
		}
		got, err := ReadControl(&wire)
		if err != nil {
			t.Fatalf("ReadControl(%s): %v", message.Type, err)
		}
		if !reflect.DeepEqual(got, message) {
			t.Fatalf("ReadControl(%s) = %#v; want %#v", message.Type, got, message)
		}
	}

	for name, payload := range map[string]string{
		"unknown field":              `{"type":"hello_accepted","protocol_version":1,"extra":true}`,
		"unknown type":               `{"type":"future","protocol_version":1}`,
		"wrong version":              `{"type":"hello_accepted","protocol_version":2}`,
		"publisher no connection":    `{"type":"hello","protocol_version":1,"role":"publisher","credential":"secret"}`,
		"ingress without credential": `{"type":"hello","protocol_version":1,"role":"ingress"}`,
		"accepted with code":         `{"type":"hello_accepted","protocol_version":1,"code":"internal"}`,
		"request without ID":         `{"type":"ping","protocol_version":1}`,
		"unknown error code":         `{"type":"error","protocol_version":1,"code":"future"}`,
		"legacy connection":          `{"type":"hello","protocol_version":1,"role":"publisher","credential":"secret","link":{"route_session_id":"session"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadControl(frame(payload)); err == nil {
				t.Fatal("ReadControl succeeded")
			}
		})
	}

	var oversized bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], MaxControlBytes+1)
	oversized.Write(header[:])
	if _, err := ReadControl(&oversized); err == nil {
		t.Fatal("oversized frame succeeded")
	}
}

func TestStreamFramesAreStrictAndBounded(t *testing.T) {
	publisherHeader := PublisherStreamHeader{
		ProtocolVersion: Version, Kind: VisitorStream, VisitorConnectionID: "visitor_connection_1",
		RouteID: "route_1", RouteSessionID: "route_session_1", RouteVersion: 2,
		PublisherConnectionID: "publisher_connection_1", ConnectionAssignmentRevision: 3,
	}
	var wire bytes.Buffer
	if err := WritePublisherStreamHeader(&wire, publisherHeader); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadPublisherStreamHeader(&wire); err != nil || got != publisherHeader {
		t.Fatalf("ReadPublisherStreamHeader = %#v, %v; want %#v", got, err, publisherHeader)
	}

	now := time.Now().UTC().Truncate(time.Second)
	internalHeader := InternalForwardingHeader{
		ProtocolVersion: Version, Kind: InternalForwardingStream, VisitorConnectionID: "visitor_connection_1",
		RouteID: "route_1", RouteSessionID: "route_session_1", RouteVersion: 2,
		PublisherConnectionID: "publisher_connection_1", ConnectionSlot: 1,
		ConnectionAssignmentRevision: 3, RelayServiceID: "relay_service_1", RelayID: "relay_1",
		RelayRunID: "relay_run_1", RelayLeaseRevision: 4,
		RouteExpiresAt: now.Add(time.Hour), LeaseExpiresAt: now.Add(time.Minute),
	}
	wire.Reset()
	if err := WriteInternalForwardingHeader(&wire, internalHeader); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadInternalForwardingHeader(&wire); err != nil || got != internalHeader {
		t.Fatalf("ReadInternalForwardingHeader = %#v, %v; want %#v", got, err, internalHeader)
	}

	responses := []StreamResponse{
		{Type: StreamAccepted},
		{Type: StreamRejected, Code: StaleConnectionAssignment},
	}
	for _, response := range responses {
		wire.Reset()
		if err := WriteStreamResponse(&wire, response); err != nil {
			t.Fatal(err)
		}
		if got, err := ReadStreamResponse(&wire); err != nil || got != response {
			t.Fatalf("ReadStreamResponse = %#v, %v; want %#v", got, err, response)
		}
	}

	for name, payload := range map[string]string{
		"unknown publisher field": `{"protocol_version":1,"kind":"visitor","visitor_connection_id":"visitor","route_id":"route","route_session_id":"session","route_version":1,"publisher_connection_id":"connection","connection_assignment_revision":1,"extra":true}`,
		"legacy hops":             `{"protocol_version":1,"kind":"visitor","visitor_connection_id":"visitor","route_id":"route","route_session_id":"session","route_version":1,"publisher_connection_id":"connection","connection_assignment_revision":1,"forward_hops":0}`,
		"accepted with code":      `{"type":"accepted","code":"internal"}`,
		"rejected without code":   `{"type":"rejected"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if strings.Contains(name, "field") || name == "legacy hops" {
				if _, err := ReadPublisherStreamHeader(frame(payload)); err == nil {
					t.Fatal("ReadPublisherStreamHeader succeeded")
				}
				return
			}
			if _, err := ReadStreamResponse(frame(payload)); err == nil {
				t.Fatal("ReadStreamResponse succeeded")
			}
		})
	}
}

func TestGoldenJSONAndFramedWireFixtures(t *testing.T) {
	assertGoldenFrame(t, "control-hello", Message{
		Type: Hello, ProtocolVersion: Version, Role: Publisher, Credential: "credential",
		PublisherConnection: &PublisherConnectionRef{
			RouteSessionID: "route_session_1", RouteID: "route_1", RouteVersion: 2,
			PublisherConnectionID: "publisher_connection_1", ConnectionSlot: 1,
			ConnectionAssignmentRevision: 3, RelayServiceID: "relay_service_1",
		},
	}, WriteControl, ReadControl)
	assertGoldenFrame(t, "publisher-stream-header", PublisherStreamHeader{
		ProtocolVersion: Version, Kind: VisitorStream, VisitorConnectionID: "visitor_connection_1",
		RouteID: "route_1", RouteSessionID: "route_session_1", RouteVersion: 2,
		PublisherConnectionID: "publisher_connection_1", ConnectionAssignmentRevision: 3,
	}, WritePublisherStreamHeader, ReadPublisherStreamHeader)
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	assertGoldenFrame(t, "internal-forwarding-header", InternalForwardingHeader{
		ProtocolVersion: Version, Kind: InternalForwardingStream, VisitorConnectionID: "visitor_connection_1",
		RouteID: "route_1", RouteSessionID: "route_session_1", RouteVersion: 2,
		PublisherConnectionID: "publisher_connection_1", ConnectionSlot: 1,
		ConnectionAssignmentRevision: 3, RelayServiceID: "relay_service_1", RelayID: "relay_1",
		RelayRunID: "relay_run_1", RelayLeaseRevision: 4,
		RouteExpiresAt: now.Add(time.Hour), LeaseExpiresAt: now.Add(time.Minute),
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
		{name: "invalid-control-unknown-field", read: func(reader io.Reader) error { _, err := ReadControl(reader); return err }},
		{name: "invalid-publisher-missing-field", read: func(reader io.Reader) error { _, err := ReadPublisherStreamHeader(reader); return err }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.read(frame(string(readFixture(t, test.name+".json")))); err == nil {
				t.Fatal("invalid fixture was accepted")
			}
		})
	}
}

func TestFramedWireFixturesRejectEveryTruncation(t *testing.T) {
	for _, test := range []struct {
		name string
		read func(io.Reader) error
	}{
		{name: "control-hello", read: func(reader io.Reader) error { _, err := ReadControl(reader); return err }},
		{name: "publisher-stream-header", read: func(reader io.Reader) error { _, err := ReadPublisherStreamHeader(reader); return err }},
		{name: "internal-forwarding-header", read: func(reader io.Reader) error { _, err := ReadInternalForwardingHeader(reader); return err }},
		{name: "stream-response", read: func(reader io.Reader) error { _, err := ReadStreamResponse(reader); return err }},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire, err := hex.DecodeString(strings.TrimSpace(string(readFixture(t, test.name+".frame.hex"))))
			if err != nil {
				t.Fatal(err)
			}
			for length := 0; length < len(wire); length++ {
				if err := test.read(bytes.NewReader(wire[:length])); err == nil {
					t.Fatalf("accepted frame truncated to %d of %d bytes", length, len(wire))
				}
			}
		})
	}
}

func FuzzReadFrames(f *testing.F) {
	var control bytes.Buffer
	if err := WriteControl(&control, Message{Type: Ping, ProtocolVersion: Version, RequestID: "request"}); err != nil {
		f.Fatal(err)
	}
	var stream bytes.Buffer
	if err := WritePublisherStreamHeader(&stream, PublisherStreamHeader{
		ProtocolVersion: Version, Kind: VisitorStream, VisitorConnectionID: "visitor",
		RouteID: "route", RouteSessionID: "session", RouteVersion: 1,
		PublisherConnectionID: "connection", ConnectionAssignmentRevision: 1,
	}); err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(0), control.Bytes(), uint8(1))
	f.Add(uint8(1), stream.Bytes(), uint8(1))
	f.Add(uint8(0), []byte{}, uint8(1))
	f.Add(uint8(1), []byte{0, 0, 0, 0}, uint8(2))

	f.Fuzz(func(t *testing.T, kind uint8, input []byte, readSize uint8) {
		reader := &limitedReader{Reader: bytes.NewReader(input), Size: int(readSize%32) + 1}
		if kind%2 == 0 {
			_, _ = ReadControl(reader)
		} else {
			_, _ = ReadPublisherStreamHeader(reader)
		}
	})
}

func frame(payload string) io.Reader {
	var result bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	result.Write(header[:])
	result.WriteString(payload)
	return &result
}

func assertGoldenFrame[T any](
	t *testing.T,
	name string,
	want T,
	write func(io.Writer, T) error,
	read func(io.Reader) (T, error),
) {
	t.Helper()
	var compactJSON bytes.Buffer
	if err := json.Compact(&compactJSON, readFixture(t, name+".json")); err != nil {
		t.Fatal(err)
	}
	wantJSON := compactJSON.Bytes()
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, wantJSON) {
		t.Fatalf("JSON = %s; want %s", encoded, wantJSON)
	}
	wantWire, err := hex.DecodeString(strings.TrimSpace(string(readFixture(t, name+".frame.hex"))))
	if err != nil {
		t.Fatal(err)
	}
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

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

type limitedReader struct {
	Reader io.Reader
	Size   int
}

func (r *limitedReader) Read(destination []byte) (int, error) {
	if len(destination) > r.Size {
		destination = destination[:r.Size]
	}
	return r.Reader.Read(destination)
}
