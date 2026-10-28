package tunnelv1

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestNativeLegActivationClosedUnionAndExactNonce(t *testing.T) {
	hello, err := ReadControl(bytes.NewReader(goldenWire(t, "control-native-hello")))
	if err != nil {
		t.Fatal(err)
	}
	binding := NativeLegBinding{Nonce: bytes.Clone(hello.NativePairLegProof.Nonce)}
	if !binding.Matches(*hello.NativePairLegProof) {
		t.Fatal("binding did not select its original signed hello")
	}
	binding.Nonce[31]++
	if binding.Matches(*hello.NativePairLegProof) {
		t.Fatal("foreign hello nonce selected this candidate")
	}
	for _, name := range []string{"control-native-activate", "control-native-activated", "control-native-handoff", "control-native-handed-off"} {
		var original map[string]json.RawMessage
		if err := json.Unmarshal(readFixture(t, name+".json"), &original); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"credential", "publisher_connection", "service_connection", "native_pair_leg_proof", "native_pair_leg_accepted", "code", "unknown"} {
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
		`{"type":"native_leg_activate","protocol_version":1,"request_id":"a","role":"native_connector"}`,
		`{"type":"native_leg_activate","protocol_version":1,"request_id":"a","role":"native_connector","native_leg_binding":{}}`,
		`{"type":"native_leg_activate","protocol_version":1,"request_id":"a","role":"native_connector","native_leg_binding":{"nonce":null}}`,
		`{"type":"native_leg_activate","protocol_version":1,"request_id":"a","role":"native_connector","native_leg_binding":{"nonce":"AQ=="}}`,
		`{"type":"native_leg_activate","protocol_version":1,"request_id":"a","role":"publisher","native_leg_binding":{"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`,
		`{"type":"native_leg_activated","protocol_version":1,"request_id":"a","role":null,"native_leg_binding":{"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`,
		`{"type":"native_leg_activate","protocol_version":1,"request_id":"a","role":"native_connector","native_leg_binding":{"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","source_ip":"127.0.0.1"}}`,
		`{"type":"ping","protocol_version":1,"request_id":"a","native_leg_binding":null}`,
	} {
		if _, err := ReadControl(frame(payload)); err == nil {
			t.Fatal("invalid activation accepted", payload)
		}
	}
	for _, kind := range []MessageType{Hello, HelloAccepted, NativeLegRenew, NativeLegRenewed, Ping, Pong, Drain, Draining, Drained, Error, GoAway} {
		if err := (Message{Type: kind, ProtocolVersion: Version, NativeLegBinding: &binding}).Validate(); err == nil {
			t.Fatal("activation binding escaped its union", kind)
		}
	}
}
