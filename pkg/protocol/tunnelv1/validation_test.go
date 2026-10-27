package tunnelv1

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
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

func TestPeerNativeHelloRoleSeparation(t *testing.T) {
	native, err := ReadControl(bytes.NewReader(goldenWire(t, "control-native-hello")))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*Message)
	}{
		{"ingress proof", func(m *Message) { m.Role = Ingress; m.Credential = "secret" }},
		{"service connection", func(m *Message) { m.ServiceConnection = &ServicePublisherConnectionRef{} }},
		{"publisher connection", func(m *Message) { m.PublisherConnection = &PublisherConnectionRef{} }},
		{"credential", func(m *Message) { m.Credential = "secret" }},
		{"response proof", func(m *Message) { m.Type = HelloAccepted; m.Role = "" }},
		{"error proof", func(m *Message) { m.Type = Error; m.Role = ""; m.Code = Unauthenticated }},
	} {
		t.Run(test.name, func(t *testing.T) {
			bad := native
			test.mutate(&bad)
			if err := bad.Validate(); err == nil {
				t.Fatal("accepted a proof outside a native connector hello")
			}
		})
	}
	nativeJSON := string(readFixture(t, "control-native-hello.json"))
	for _, field := range []string{`"credential":""`, `"publisher_connection":null`, `"service_connection":null`} {
		if err := readControl(frame(strings.Replace(nativeJSON, `"role": "native_connector",`, `"role": "native_connector",`+field+`,`, 1))); err == nil {
			t.Fatalf("native hello accepted forbidden field %s", field)
		}
	}
	for _, kind := range []string{`"role":"ingress","credential":"secret"`, `"role":"publisher","credential":"secret"`} {
		if err := readControl(frame(`{"type":"hello","protocol_version":1,` + kind + `,"native_pair_leg_proof":null}`)); err == nil {
			t.Fatalf("non-native role accepted null proof: %s", kind)
		}
	}
}

func TestPeerNativeReceiptBindingAndInvalidWire(t *testing.T) {
	hello, err := ReadControl(bytes.NewReader(goldenWire(t, "control-native-hello")))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := ReadControl(bytes.NewReader(goldenWire(t, "control-native-accepted")))
	if err != nil {
		t.Fatal(err)
	}
	receipt := *accepted.NativePairLegAccepted
	// the accepted fixture describes the second leg of the same pair.
	proof := *hello.NativePairLegProof
	proof.ConnectionSlot = receipt.ConnectionSlot
	before := receipt.ExpiresAt.Add(-time.Second)
	if err := receipt.Match(proof, receipt.DeliveryID, before); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*NativePairLegAccepted, *NativePairLegProof, *string, *time.Time)
	}{
		{"pair", func(r *NativePairLegAccepted, _ *NativePairLegProof, _ *string, _ *time.Time) {
			r.PairID = "npp_abcdefghijklmnopqrstuv"
		}},
		{"generation", func(r *NativePairLegAccepted, _ *NativePairLegProof, _ *string, _ *time.Time) { r.DeliveryGeneration++ }},
		{"slot", func(r *NativePairLegAccepted, _ *NativePairLegProof, _ *string, _ *time.Time) { r.ConnectionSlot = 0 }},
		{"delivery", func(r *NativePairLegAccepted, _ *NativePairLegProof, _ *string, _ *time.Time) {
			r.DeliveryID = "AgICAgICAgICAgICAgICAg"
		}},
		{"expected delivery", func(_ *NativePairLegAccepted, _ *NativePairLegProof, id *string, _ *time.Time) {
			*id = "AgICAgICAgICAgICAgICAg"
		}},
		{"invalid expected delivery", func(_ *NativePairLegAccepted, _ *NativePairLegProof, id *string, _ *time.Time) { *id = "bad" }},
		{"expired", func(_ *NativePairLegAccepted, _ *NativePairLegProof, _ *string, now *time.Time) {
			*now = receipt.ExpiresAt
		}},
		{"missing expiry", func(r *NativePairLegAccepted, _ *NativePairLegProof, _ *string, _ *time.Time) {
			r.ExpiresAt = time.Time{}
		}},
		{"untrusted source", func(r *NativePairLegAccepted, _ *NativePairLegProof, _ *string, _ *time.Time) {
			r.SourceIP = "not-an-ip"
		}},
		{"unspecified source", func(r *NativePairLegAccepted, _ *NativePairLegProof, _ *string, _ *time.Time) { r.SourceIP = "0.0.0.0" }},
		{"mapped source", func(r *NativePairLegAccepted, _ *NativePairLegProof, _ *string, _ *time.Time) {
			r.SourceIP = "::ffff:192.0.2.10"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, leg, id, now := receipt, proof, receipt.DeliveryID, before
			test.change(&r, &leg, &id, &now)
			if err := r.Match(leg, id, now); err == nil {
				t.Fatal("accepted an unbound native receipt")
			}
		})
	}
	for _, kind := range []MessageType{Hello, Ping, Drain, Error, GoAway} {
		bad := accepted
		bad.Type = kind
		bad.Code = Unauthenticated
		bad.RequestID = "req"
		if err := bad.Validate(); err == nil {
			t.Fatalf("accepted receipt on %s", kind)
		}
	}
	for _, raw := range []string{
		`{"type":"hello_accepted","protocol_version":1,"native_pair_leg_accepted":null}`,
		`{"type":"hello_accepted","protocol_version":1,"native_pair_leg_accepted": null }`,
		`{"type":"hello_accepted","protocol_version":1,"role":"publisher","native_pair_leg_accepted":null}`,
		`{"type":"error","protocol_version":1,"code":"internal","native_pair_leg_accepted":null}`,
	} {
		if err := readControl(frame(raw)); err == nil {
			t.Fatal("accepted receipt on another role or message")
		}
	}
}

func TestDeniedPolicyMarkerSurvivesBothStreamHeaders(t *testing.T) {
	visitor, err := ReadVisitorStreamHeader(bytes.NewReader(goldenWire(t, "visitor-stream-header")))
	if err != nil {
		t.Fatal(err)
	}
	visitor.AccessPending = true
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
	forward.AccessPending = true
	wire.Reset()
	if err := WriteInternalForwardingHeader(&wire, forward); err != nil {
		t.Fatal(err)
	}
	if received, err := ReadInternalForwardingHeader(&wire); err != nil || received != forward {
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
		{"unsupported version", `{"type":"hello_accepted","protocol_version":2}`, readControl},
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
	for _, site := range []string{"sjc", "local", "SJC", "na", "unknown"} {
		input := strings.Replace(forward, `"protocol_version":1,`, `"protocol_version":1,"ingress_region":"`+site+`",`, 1)
		if err := readForwarding(frame(input)); (err == nil) != (site == "sjc" || site == "local") {
			t.Fatalf("ingress region %s: %v", site, err)
		}
	}
}
