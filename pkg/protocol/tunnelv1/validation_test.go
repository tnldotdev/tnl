package tunnelv1

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestControlMessages(t *testing.T) {
	connection := &PublisherConnectionRef{PublishRunID: "publish_run_1", PublicURLID: "public_url_1", PublishRunNumber: 2, PublisherConnectionID: "publisher_connection_1", ConnectionSlot: 1, ConnectionAssignmentRevision: 3, RelayServiceID: "relay_service_1"}
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

func TestDeniedPolicyMarkerSurvivesBothStreamHeaders(t *testing.T) {
	visitor, err := ReadVisitorStreamHeader(bytes.NewReader(goldenWire(t, "visitor-stream-header")))
	if err != nil {
		t.Fatal(err)
	}
	visitor.IPPolicyDenied = true
	var wire bytes.Buffer
	if err := WriteVisitorStreamHeader(&wire, visitor); err != nil {
		t.Fatal(err)
	}
	if received, err := ReadVisitorStreamHeader(&wire); err != nil || received != visitor {
		t.Fatalf("visitor header = %+v, %v", received, err)
	}
	forward, err := ReadInternalForwardingHeader(bytes.NewReader(goldenWire(t, "internal-forwarding-header")))
	if err != nil {
		t.Fatal(err)
	}
	forward.IPPolicyDenied = true
	wire.Reset()
	if err := WriteInternalForwardingHeader(&wire, forward); err != nil {
		t.Fatal(err)
	}
	if received, err := ReadInternalForwardingHeader(&wire); err != nil || received != forward {
		t.Fatalf("forwarding header = %+v, %v", received, err)
	}
}

func TestAdmissionDecisionRequiresCurrentPublisherAndRelayIdentity(t *testing.T) {
	publisher := AdmissionHeader{
		ProtocolVersion: Version, Kind: PublisherAdmissionStream,
		VisitorConnectionID: "visitor_connection_1", PublicURLID: "public_url_1", PublishRunID: "publish_run_1",
		PublishRunNumber: 2, PublisherConnectionID: "publisher_connection_1",
		ConnectionAssignmentRevision: 3, RelayServiceID: "relay_service_1",
	}
	var wire bytes.Buffer
	if err := WriteAdmissionHeader(&wire, publisher); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadAdmissionHeader(&wire); err != nil || got != publisher {
		t.Fatalf("publisher decision = %+v, %v", got, err)
	}
	ingress := publisher
	ingress.Kind, ingress.RelayID, ingress.RelayRunID, ingress.RelayLeaseRevision = IngressAdmissionStream, "relay_1", "relay_run_1", 4
	if err := WriteAdmissionHeader(&wire, ingress); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadAdmissionHeader(&wire); err != nil || got != ingress {
		t.Fatalf("ingress decision = %+v, %v", got, err)
	}
	for _, invalid := range []AdmissionHeader{
		{Kind: PublisherAdmissionStream},
		{ProtocolVersion: Version + 1, Kind: PublisherAdmissionStream, VisitorConnectionID: publisher.VisitorConnectionID,
			PublicURLID: publisher.PublicURLID, PublishRunID: publisher.PublishRunID, PublishRunNumber: publisher.PublishRunNumber,
			PublisherConnectionID: publisher.PublisherConnectionID, ConnectionAssignmentRevision: publisher.ConnectionAssignmentRevision,
			RelayServiceID: publisher.RelayServiceID},
		func() AdmissionHeader { value := publisher; value.RelayID = "relay_1"; return value }(),
		func() AdmissionHeader { value := ingress; value.RelayLeaseRevision = 0; return value }(),
	} {
		if err := WriteAdmissionHeader(&wire, invalid); err == nil {
			t.Fatalf("invalid admission header was accepted: %+v", invalid)
		}
	}
	for _, result := range []AdmissionResult{{Type: StreamAccepted}, {Type: StreamRejected, Code: CapacityExceeded}} {
		if err := WriteAdmissionResult(&wire, result); err != nil {
			t.Fatal(err)
		}
		if got, err := ReadAdmissionResult(&wire); err != nil || got != result {
			t.Fatalf("admission acknowledgement = %+v, %v", got, err)
		}
	}
	if err := WriteAdmissionResult(&wire, AdmissionResult{Type: StreamAccepted, Code: Internal}); err == nil {
		t.Fatal("accepted decision carried an error code")
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
		{"legacy connection", `{"type":"hello","protocol_version":1,"role":"publisher","credential":"secret","link":{"publish_run_id":"session"}}`, readControl},
		{"unknown publisher field", `{"protocol_version":1,"kind":"visitor","visitor_connection_id":"visitor","public_url_id":"route","publish_run_id":"session","publish_run_number":1,"publisher_connection_id":"connection","connection_assignment_revision":1,"extra":true}`, readVisitor},
		{"legacy hops", `{"protocol_version":1,"kind":"visitor","visitor_connection_id":"visitor","public_url_id":"route","publish_run_id":"session","publish_run_number":1,"publisher_connection_id":"connection","connection_assignment_revision":1,"forward_hops":0}`, readVisitor},
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
			for _, field := range []string{`"publish_run_number":2`, `"connection_assignment_revision":3`} {
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
