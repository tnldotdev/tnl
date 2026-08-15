package tunnelv1

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestControlMessages(t *testing.T) {
	connection := &PublisherConnectionRef{RouteSessionID: "route_session_1", RouteID: "route_1", RouteVersion: 2, PublisherConnectionID: "publisher_connection_1", ConnectionSlot: 1, ConnectionAssignmentRevision: 3, RelayServiceID: "relay_service_1"}
	for _, message := range []Message{
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
	} {
		var wire bytes.Buffer
		if err := WriteControl(&wire, message); err != nil {
			t.Fatal(err)
		}
		if got, err := ReadControl(&wire); err != nil || !reflect.DeepEqual(got, message) {
			t.Fatalf("%s: got %#v, %v", message.Type, got, err)
		}
	}
	for _, response := range []StreamResponse{{Type: StreamAccepted}, {Type: StreamRejected, Code: StaleConnectionAssignment}} {
		var wire bytes.Buffer
		if err := WriteStreamResponse(&wire, response); err != nil {
			t.Fatal(err)
		}
		if got, err := ReadStreamResponse(&wire); err != nil || got != response {
			t.Fatalf("response=%+v, %v", got, err)
		}
	}
}

func TestReadersRejectInvalidMessages(t *testing.T) {
	for _, test := range []struct {
		name, payload string
		read          func(io.Reader) error
	}{
		{"unknown control field", `{"type":"hello_accepted","protocol_version":1,"extra":true}`, readControl},
		{"unknown type", `{"type":"future","protocol_version":1}`, readControl},
		{"wrong version", `{"type":"hello_accepted","protocol_version":2}`, readControl},
		{"publisher no connection", `{"type":"hello","protocol_version":1,"role":"publisher","credential":"secret"}`, readControl},
		{"ingress without credential", `{"type":"hello","protocol_version":1,"role":"ingress"}`, readControl},
		{"accepted with code", `{"type":"hello_accepted","protocol_version":1,"code":"internal"}`, readControl},
		{"request without ID", `{"type":"ping","protocol_version":1}`, readControl},
		{"unknown error code", `{"type":"error","protocol_version":1,"code":"future"}`, readControl},
		{"legacy connection", `{"type":"hello","protocol_version":1,"role":"publisher","credential":"secret","link":{"route_session_id":"session"}}`, readControl},
		{"unknown publisher field", `{"protocol_version":1,"kind":"visitor","visitor_connection_id":"visitor","route_id":"route","route_session_id":"session","route_version":1,"publisher_connection_id":"connection","connection_assignment_revision":1,"extra":true}`, readVisitor},
		{"legacy hops", `{"protocol_version":1,"kind":"visitor","visitor_connection_id":"visitor","route_id":"route","route_session_id":"session","route_version":1,"publisher_connection_id":"connection","connection_assignment_revision":1,"forward_hops":0}`, readVisitor},
		{"stream accepted with code", `{"type":"accepted","code":"internal"}`, readResponse},
		{"rejected without code", `{"type":"rejected"}`, readResponse},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.read(frame(test.payload)); err == nil {
				t.Fatal("invalid message accepted")
			}
		})
	}
}

func TestStreamFieldBounds(t *testing.T) {
	for _, test := range []struct {
		name string
		read func(io.Reader) error
	}{
		{"visitor-stream-header", readVisitor},
		{"internal-forwarding-header", readForwarding},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := string(goldenWire(t, test.name)[4:])
			for _, length := range []int{0, 256, 257} {
				input := strings.Replace(payload, `"visitor_connection_1"`, `"`+strings.Repeat("v", length)+`"`, 1)
				err := test.read(frame(input))
				if (err == nil) != (length == 256) {
					t.Fatalf("identifier length %d: %v", length, err)
				}
			}
			for _, field := range []string{`"route_version":2`, `"connection_assignment_revision":3`} {
				invalid := strings.Replace(payload, field, field[:len(field)-1]+"0", 1)
				if err := test.read(frame(invalid)); err == nil {
					t.Fatalf("accepted zero %s", field)
				}
			}
		})
	}
	forward := string(goldenWire(t, "internal-forwarding-header")[4:])
	for _, slot := range []string{"0", "1", "2"} {
		input := strings.Replace(forward, `"connection_slot":1`, `"connection_slot":`+slot, 1)
		if err := readForwarding(frame(input)); (err == nil) != (slot != "2") {
			t.Fatalf("slot %s: %v", slot, err)
		}
	}
}
