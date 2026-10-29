package tunnelv1

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestNativeLegHandoffRequiresDistinctExactPredecessor(t *testing.T) {
	for _, name := range []string{"control-native-handoff", "control-native-handed-off"} {
		for _, value := range []string{`null`, `""`, `"AQ=="`, `"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="`} {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(readFixture(t, name+".json"), &fields); err != nil {
				t.Fatal(err)
			}
			var binding map[string]json.RawMessage
			if err := json.Unmarshal(fields["native_leg_binding"], &binding); err != nil {
				t.Fatal(err)
			}
			binding["previous_nonce"] = json.RawMessage(value)
			fields["native_leg_binding"], _ = json.Marshal(binding)
			payload, _ := json.Marshal(fields)
			if _, err := ReadControl(frame(string(payload))); err == nil {
				t.Fatal("invalid predecessor accepted", name, value)
			}
		}
	}
	for _, kind := range []MessageType{NativeLegActivate, NativeLegActivated, NativeLegHandoff, NativeLegHandedOff} {
		binding := NativeLegBinding{Nonce: make([]byte, 32)}
		if kind == NativeLegActivate || kind == NativeLegActivated {
			binding.PreviousNonce = bytes.Repeat([]byte{1}, 32)
		}
		role := NativeConnector
		if kind == NativeLegActivated || kind == NativeLegHandedOff {
			role = ""
		}
		if err := (Message{Type: kind, ProtocolVersion: Version, RequestID: "select", Role: role, NativeLegBinding: &binding}).Validate(); err == nil {
			t.Fatal("startup and handoff accepted interchangeable bindings", kind)
		}
	}
}
