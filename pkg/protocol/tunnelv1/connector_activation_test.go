package tunnelv1

import (
	"bytes"
	"encoding/json"
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
