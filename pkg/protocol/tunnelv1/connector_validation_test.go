package tunnelv1

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestPeerConnectorHelloRoleSeparation(t *testing.T) {
	connector, err := ReadControl(bytes.NewReader(goldenWire(t, "control-connector-hello")))
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
			bad := connector
			test.mutate(&bad)
			if err := bad.Validate(); err == nil {
				t.Fatal("accepted a proof outside a connector hello")
			}
		})
	}
	connectorJSON := string(readFixture(t, "control-connector-hello.json"))
	for _, field := range []string{`"credential":""`, `"publisher_connection":null`, `"service_connection":null`} {
		if err := readControl(frame(strings.Replace(connectorJSON, `"role": "connector",`, `"role": "connector",`+field+`,`, 1))); err == nil {
			t.Fatalf("connector hello accepted forbidden field %s", field)
		}
	}
	for _, kind := range []string{`"role":"ingress","credential":"secret"`, `"role":"publisher","credential":"secret"`} {
		if err := readControl(frame(`{"type":"hello","protocol_version":1,` + kind + `,"connector_pair_leg_proof":null}`)); err == nil {
			t.Fatalf("non-connector role accepted null proof: %s", kind)
		}
	}
}

func TestConnectorVocabularyRejectsRetiredWireNames(t *testing.T) {
	hello := string(readFixture(t, "control-connector-hello.json"))
	for _, test := range []struct{ name, old, replacement string }{
		{"role", `"role": "connector"`, `"role": "native_connector"`},
		{"proof", `"connector_pair_leg_proof"`, `"native_pair_leg_proof"`},
		{"pair id", `cpp_`, `npp_`},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := strings.Replace(hello, test.old, test.replacement, 1)
			if changed == hello {
				t.Fatal("fixture did not contain the renamed field")
			}
			if err := readControl(frame(changed)); err == nil {
				t.Fatal("retired connector vocabulary was accepted")
			}
		})
	}
}

func TestPeerConnectorReceiptBindingAndInvalidWire(t *testing.T) {
	hello, err := ReadControl(bytes.NewReader(goldenWire(t, "control-connector-hello")))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := ReadControl(bytes.NewReader(goldenWire(t, "control-connector-accepted")))
	if err != nil {
		t.Fatal(err)
	}
	receipt := *accepted.ConnectorPairLegAccepted
	// the accepted fixture describes the second leg of the same pair.
	proof := *hello.ConnectorPairLegProof
	proof.ConnectionSlot = receipt.ConnectionSlot
	before := receipt.ExpiresAt.Add(-time.Second)
	if err := receipt.Match(proof, receipt.DeliveryID, receipt.ObservedAt, before); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*ConnectorPairLegAccepted, *ConnectorPairLegProof, *string, *time.Time)
	}{
		{"pair", func(r *ConnectorPairLegAccepted, _ *ConnectorPairLegProof, _ *string, _ *time.Time) {
			r.PairID = "cpp_abcdefghijklmnopqrstuv"
		}},
		{"generation", func(r *ConnectorPairLegAccepted, _ *ConnectorPairLegProof, _ *string, _ *time.Time) {
			r.DeliveryGeneration++
		}},
		{"slot", func(r *ConnectorPairLegAccepted, _ *ConnectorPairLegProof, _ *string, _ *time.Time) {
			r.ConnectionSlot = 0
		}},
		{"delivery", func(r *ConnectorPairLegAccepted, _ *ConnectorPairLegProof, _ *string, _ *time.Time) {
			r.DeliveryID = "AgICAgICAgICAgICAgICAg"
		}},
		{"expected delivery", func(_ *ConnectorPairLegAccepted, _ *ConnectorPairLegProof, id *string, _ *time.Time) {
			*id = "AgICAgICAgICAgICAgICAg"
		}},
		{"invalid expected delivery", func(_ *ConnectorPairLegAccepted, _ *ConnectorPairLegProof, id *string, _ *time.Time) { *id = "bad" }},
		{"expired", func(_ *ConnectorPairLegAccepted, _ *ConnectorPairLegProof, _ *string, now *time.Time) {
			*now = receipt.ExpiresAt
		}},
		{"missing expiry", func(r *ConnectorPairLegAccepted, _ *ConnectorPairLegProof, _ *string, _ *time.Time) {
			r.ExpiresAt = time.Time{}
		}},
		{"missing observation", func(r *ConnectorPairLegAccepted, _ *ConnectorPairLegProof, _ *string, _ *time.Time) {
			r.ObservedAt = time.Time{}
		}},
		{"excess authority", func(r *ConnectorPairLegAccepted, _ *ConnectorPairLegProof, _ *string, _ *time.Time) {
			r.ExpiresAt = r.ObservedAt.Add(5*time.Minute + time.Nanosecond)
		}},
		{"untrusted source", func(r *ConnectorPairLegAccepted, _ *ConnectorPairLegProof, _ *string, _ *time.Time) {
			r.SourceIP = "not-an-ip"
		}},
		{"unspecified source", func(r *ConnectorPairLegAccepted, _ *ConnectorPairLegProof, _ *string, _ *time.Time) {
			r.SourceIP = "0.0.0.0"
		}},
		{"mapped source", func(r *ConnectorPairLegAccepted, _ *ConnectorPairLegProof, _ *string, _ *time.Time) {
			r.SourceIP = "::ffff:192.0.2.10"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, leg, id, now := receipt, proof, receipt.DeliveryID, before
			test.change(&r, &leg, &id, &now)
			if err := r.Match(leg, id, receipt.ObservedAt, now); err == nil {
				t.Fatal("accepted an unbound connector receipt")
			}
		})
	}
	for _, skew := range []time.Duration{-time.Hour, time.Hour} {
		r := receipt
		r.ObservedAt, r.ExpiresAt = r.ObservedAt.Add(skew), r.ExpiresAt.Add(skew)
		if err := r.Match(proof, r.DeliveryID, receipt.ObservedAt, before); err != nil {
			t.Fatal("relay clock skew changed the observed remaining authority", err)
		}
		if err := r.Match(proof, r.DeliveryID, receipt.ObservedAt, receipt.ExpiresAt); err == nil {
			t.Fatal("transit revived expired relay authority")
		}
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
		`{"type":"hello_accepted","protocol_version":1,"connector_pair_leg_accepted":null}`,
		`{"type":"hello_accepted","protocol_version":1,"connector_pair_leg_accepted": null }`,
		`{"type":"hello_accepted","protocol_version":1,"role":"publisher","connector_pair_leg_accepted":null}`,
		`{"type":"error","protocol_version":1,"code":"internal","connector_pair_leg_accepted":null}`,
	} {
		if err := readControl(frame(raw)); err == nil {
			t.Fatal("accepted receipt on another role or message")
		}
	}
}
