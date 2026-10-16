package config

import (
	"testing"

	"encoding/json/v2"

	"go.yaml.in/yaml/v3"
)

func TestAccessConfigurationRequiresCredentialsUnlessAnonymous(t *testing.T) {
	for _, tc := range []struct {
		input string
		mode  string
		ip    string
	}{
		{`"restricted"`, "restricted", ""},
		{`"anonymous"`, "anonymous", ""},
		{`{"ip":["192.0.2.0/24"]}`, "restricted", "192.0.2.0/24"},
		{`{"mode":"anonymous","ip":["192.0.2.0/24"]}`, "anonymous", "192.0.2.0/24"},
	} {
		var value Access
		if err := json.Unmarshal([]byte(tc.input), &value); err != nil || value.VisitorMode() != tc.mode {
			t.Fatalf("access %s: %+v, %v", tc.input, value, err)
		}
		if tc.ip != "" && (len(value.IP) != 1 || value.IP[0] != tc.ip) {
			t.Fatalf("IP access %s: %+v", tc.input, value)
		}
	}
	for _, input := range []string{`{"mode":"*"}`, `{"ip":[]}`, `{"ip":["192.0.2.1","192.0.2.1/32"]}`, `{"other":true}`} {
		var value Access
		if err := json.Unmarshal([]byte(input), &value); err == nil {
			t.Fatalf("invalid access %s was accepted", input)
		}
	}
	var yamlValue Access
	if err := yaml.Unmarshal([]byte("mode: anonymous\nip: [192.0.2.0/24]"), &yamlValue); err != nil || yamlValue.VisitorMode() != "anonymous" || len(yamlValue.IP) != 1 {
		t.Fatalf("YAML access: %+v, %v", yamlValue, err)
	}
}
