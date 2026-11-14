package httpprotection

import (
	"encoding/json"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestChallengeConfiguration(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want Challenge
	}{{`"turnstile"`, Turnstile}, {`false`, ""}} {
		var setting Challenge
		if err := json.Unmarshal([]byte(tc.raw), &setting); err != nil || setting != tc.want {
			t.Fatal("valid JSON challenge rejected", tc.raw, setting, err)
		}
		encoded, err := json.Marshal(setting)
		if err != nil || string(encoded) != tc.raw {
			t.Fatal("challenge did not round trip", string(encoded), err)
		}
		if err := yaml.Unmarshal([]byte(tc.raw), &setting); err != nil || setting != tc.want {
			t.Fatal("valid YAML challenge rejected", setting, err)
		}
	}
	for _, raw := range []string{`true`, `null`, `""`, `"off"`, `"false"`, `{}`, `[]`, `1`} {
		var setting Challenge
		if err := json.Unmarshal([]byte(raw), &setting); err == nil {
			t.Fatal("accepted unsupported challenge", raw)
		}
	}
	for _, mode := range []Mode{Block, Detect, Off} {
		if err := (Settings{WAF: mode, Challenge: Turnstile}).Validate(); err != nil {
			t.Fatal("challenge was tied to WAF mode", mode, err)
		}
	}
	if err := (Settings{Challenge: "unknown"}).Validate(); err == nil {
		t.Fatal("accepted unsupported challenge in Go settings")
	}
}
