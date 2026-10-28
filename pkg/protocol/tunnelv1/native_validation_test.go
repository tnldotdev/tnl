package tunnelv1

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

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
	if err := receipt.Match(proof, receipt.DeliveryID, receipt.ObservedAt, before); err != nil {
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
		{"missing observation", func(r *NativePairLegAccepted, _ *NativePairLegProof, _ *string, _ *time.Time) {
			r.ObservedAt = time.Time{}
		}},
		{"excess authority", func(r *NativePairLegAccepted, _ *NativePairLegProof, _ *string, _ *time.Time) {
			r.ExpiresAt = r.ObservedAt.Add(5*time.Minute + time.Nanosecond)
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
			if err := r.Match(leg, id, receipt.ObservedAt, now); err == nil {
				t.Fatal("accepted an unbound native receipt")
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
