package tunnelv1

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
)

func TestConnectorLegActivationClosedUnionAndExactNonce(t *testing.T) {
	hello, err := ReadControl(bytes.NewReader(goldenWire(t, "control-connector-hello")))
	if err != nil {
		t.Fatal(err)
	}
	binding := ConnectorLegBinding{Nonce: bytes.Clone(hello.ConnectorPairLegProof.Nonce)}
	if !binding.Matches(*hello.ConnectorPairLegProof) {
		t.Fatal("binding did not select its original signed hello")
	}
	binding.Nonce[31]++
	if binding.Matches(*hello.ConnectorPairLegProof) {
		t.Fatal("foreign hello nonce selected this candidate")
	}
	for _, name := range []string{"control-connector-activate", "control-connector-activated"} {
		var original map[string]json.RawMessage
		if err := json.Unmarshal(readFixture(t, name+".json"), &original); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"credential", "publisher_connection", "service_connection", "connector_pair_leg_proof", "connector_pair_leg_accepted", "code", "unknown"} {
			for _, value := range []string{`null`, `""`, `{}`} {
				t.Run(name+"/"+field+"/"+value, func(t *testing.T) {
					original[field] = json.RawMessage(value)
					payload, err := json.Marshal(original)
					delete(original, field)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := ReadControl(frame(string(payload))); err == nil {
						t.Fatal("activation accepted a foreign field")
					}
				})
			}
		}
	}
	for _, payload := range []string{
		`{"type":"connector_leg_activate","protocol_version":1,"request_id":"a","role":"connector"}`,
		`{"type":"connector_leg_activate","protocol_version":1,"request_id":"a","role":"connector","connector_leg_binding":{}}`,
		`{"type":"connector_leg_activate","protocol_version":1,"request_id":"a","role":"connector","connector_leg_binding":{"nonce":null}}`,
		`{"type":"connector_leg_activate","protocol_version":1,"request_id":"a","role":"connector","connector_leg_binding":{"nonce":"AQ=="}}`,
		`{"type":"connector_leg_activate","protocol_version":1,"request_id":"a","role":"publisher","connector_leg_binding":{"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`,
		`{"type":"connector_leg_activated","protocol_version":1,"request_id":"a","role":null,"connector_leg_binding":{"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`,
		`{"type":"connector_leg_activate","protocol_version":1,"request_id":"a","role":"connector","connector_leg_binding":{"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","source_ip":"127.0.0.1"}}`,
		`{"type":"ping","protocol_version":1,"request_id":"a","connector_leg_binding":null}`,
	} {
		if _, err := ReadControl(frame(payload)); err == nil {
			t.Fatal("invalid activation accepted", payload)
		}
	}
	for _, kind := range []MessageType{Hello, HelloAccepted, ConnectorLegRenew, ConnectorLegRenewed, Ping, Pong, Drain, Draining, Drained, Error, GoAway} {
		if err := (Message{Type: kind, ProtocolVersion: Version, ConnectorLegBinding: &binding}).Validate(); err == nil {
			t.Fatal("activation binding escaped its union", kind)
		}
	}
}

func TestConnectorLegReplacementBindingRoundTrip(t *testing.T) {
	binding := ConnectorLegBinding{Nonce: bytes.Repeat([]byte{1}, 32), PreviousNonce: bytes.Repeat([]byte{2}, 32), ReplacementNonce: bytes.Repeat([]byte{3}, 32)}
	message := Message{Type: ConnectorLegActivate, ProtocolVersion: Version, RequestID: "repair", Role: Connector, ConnectorLegBinding: &binding}
	var wire bytes.Buffer
	if err := WriteControl(&wire, message); err != nil {
		t.Fatal(err)
	}
	const golden = `{"type":"connector_leg_activate","protocol_version":1,"request_id":"repair","role":"connector","connector_leg_binding":{"nonce":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","previous_nonce":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","replacement_nonce":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="}}`
	want, err := io.ReadAll(frame(golden))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire.Bytes(), want) {
		t.Fatalf("replacement wire changed: %s", wire.Bytes()[4:])
	}
	got, err := ReadControl(&wire)
	if err != nil || !bytes.Equal(got.ConnectorLegBinding.PreviousNonce, binding.PreviousNonce) || !bytes.Equal(got.ConnectorLegBinding.ReplacementNonce, binding.ReplacementNonce) {
		t.Fatal("replacement binding lost", err)
	}
	for _, mutate := range []func(*ConnectorLegBinding){
		func(b *ConnectorLegBinding) { b.PreviousNonce = nil },
		func(b *ConnectorLegBinding) { b.ReplacementNonce = nil },
		func(b *ConnectorLegBinding) { b.ReplacementNonce = b.PreviousNonce },
		func(b *ConnectorLegBinding) { b.PreviousNonce = b.PreviousNonce[:31] },
	} {
		invalid := binding
		mutate(&invalid)
		if invalid.Validate() == nil {
			t.Fatal("partial or self-replacing handoff accepted")
		}
	}
}

func TestConnectorActivationCopiesAndDistinguishesIdentities(t *testing.T) {
	binding := ConnectorLegBinding{Nonce: bytes.Repeat([]byte{1}, 32), PreviousNonce: bytes.Repeat([]byte{2}, 32), ReplacementNonce: bytes.Repeat([]byte{3}, 32)}
	activation, err := binding.Activation()
	if err != nil {
		t.Fatal(err)
	}
	handoff, replacement := activation.Replacement()
	if !replacement || activation.Hello() != (ConnectorHelloNonce(bytes.Repeat([]byte{1}, 32))) || handoff.Previous() != (ConnectorHandoffID(bytes.Repeat([]byte{2}, 32))) || activation.SelectedHandoff() != handoff.Next() {
		t.Fatal("identity roles changed")
	}
	binding.Nonce[0]++
	binding.PreviousNonce[0]++
	binding.ReplacementNonce[0]++
	wire := activation.Binding()
	if wire.Nonce[0] != 1 || wire.PreviousNonce[0] != 2 || wire.ReplacementNonce[0] != 3 {
		t.Fatal("validated identities aliased wire bytes")
	}
	wire.Nonce[0]++
	if activation.Binding().Nonce[0] != 1 {
		t.Fatal("wire serialization aliased validated identity")
	}
	if _, err := NewConnectorHandoff(handoff.Next(), handoff.Next()); err == nil || (ConnectorHandoff{}).Valid() {
		t.Fatal("self replacement accepted")
	}
}
