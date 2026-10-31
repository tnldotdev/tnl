package tunnelv1

import (
	"encoding/json"
	"testing"
)

func TestNativeCarrierReplacementIsNotAControlOperation(t *testing.T) {
	for _, kind := range []string{"native_leg_handoff", "native_leg_handed_off"} {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(readFixture(t, "control-native-activate.json"), &fields); err != nil {
			t.Fatal(err)
		}
		fields["type"], _ = json.Marshal(kind)
		payload, _ := json.Marshal(fields)
		if _, err := ReadControl(frame(string(payload))); err == nil {
			t.Fatal("carrier replacement accepted", kind)
		}
	}
	for _, name := range []string{"control-native-activate", "control-native-activated"} {
		for _, value := range []string{`null`, `""`, `"AQ=="`} {
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
				t.Fatal("activation accepted a predecessor", name, value)
			}
		}
	}
}
