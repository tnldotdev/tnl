package tunnelv1

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestControlMessages(t *testing.T) {
	connection := &ServicePublisherConnectionRef{ServiceID: "svc_1234567890123456789012", ServiceRunID: "srun_1234567890123456789012", RunNumber: 2, PublisherConnectionID: "pc_1234567890123456789012", ConnectionSlot: 1, ConnectionAssignmentRevision: 3, RelayServiceID: "relay_service_1"}
	for _, message := range []Message{
		{Type: Hello, ProtocolVersion: Version, Role: Publisher, Credential: "secret", ServiceConnection: connection},
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
	for _, response := range []ReturnFrame{{Kind: ReturnAccepted}, {Kind: ReturnRejected, Code: StaleConnectionAssignment}} {
		var wire bytes.Buffer
		if err := WriteReturnFrame(&wire, response); err != nil {
			t.Fatal(err)
		}
		if got, err := ReadReturnFrame(&wire); err != nil || !reflect.DeepEqual(got, response) {
			t.Fatalf("response=%+v, %v", got, err)
		}
	}
}

func TestServiceHeaderPreservesIngressAndSource(t *testing.T) {
	header, err := ReadServiceForwardingHeader(bytes.NewReader(goldenWire(t, "service-forwarding-header")))
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := WriteServiceForwardingHeader(&wire, header); err != nil {
		t.Fatal(err)
	}
	if received, err := ReadServiceForwardingHeader(&wire); err != nil || !reflect.DeepEqual(received, header) {
		t.Fatalf("forwarding header = %+v, %v", received, err)
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
		{"legacy connection", `{"type":"hello","protocol_version":1,"role":"publisher","credential":"secret","publisher_connection":{"publish_run_id":"session"}}`, readControl},
		{"old visitor stream", `{"protocol_version":1,"kind":"visitor","visitor_connection_id":"visitor","public_url_id":"route"}`, readServiceForwarding},
		{"old forwarding header", `{"protocol_version":1,"kind":"internal_forward","visitor_connection_id":"visitor","public_url_id":"route"}`, readServiceForwarding},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.read(frame(test.payload)); err == nil {
				t.Fatal("invalid message accepted")
			}
		})
	}
}

func TestStreamFieldBounds(t *testing.T) {
	forward := string(goldenWire(t, "service-forwarding-header")[4:])
	for _, field := range []string{`"run_number":2`, `"connection_assignment_revision":3`} {
		invalid := strings.Replace(forward, field, field[:len(field)-1]+"0", 1)
		if err := readServiceForwarding(frame(invalid)); err == nil {
			t.Fatalf("accepted zero %s", field)
		}
	}
	for _, source := range []string{`"192.0.2.1"`, `"192.0.2.1%spoof"`} {
		input := strings.Replace(forward, `"192.0.2.1"`, source, 1)
		if err := readServiceForwarding(frame(input)); (err == nil) != (source == `"192.0.2.1"`) {
			t.Fatalf("source %s: %v", source, err)
		}
	}
	for _, slot := range []string{"0", "1", "2"} {
		input := strings.Replace(forward, `"connection_slot":1`, `"connection_slot":`+slot, 1)
		if err := readServiceForwarding(frame(input)); (err == nil) != (slot != "2") {
			t.Fatalf("slot %s: %v", slot, err)
		}
	}
}
