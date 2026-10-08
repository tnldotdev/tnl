package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestWebhookSourcesJSONAndYAML(t *testing.T) {
	for _, test := range []struct {
		name, json, yaml string
		any              bool
	}{
		{"all", `"*"`, `"*"`, true},
		{"restricted", `{"providers":["stripe"],"ips":["198.51.100.0/24"]}`, "providers: [stripe]\nips: [198.51.100.0/24]", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var fromJSON, fromYAML WebhookSources
			if err := json.Unmarshal([]byte(test.json), &fromJSON); err != nil {
				t.Fatal(err)
			}
			if err := yaml.Unmarshal([]byte(test.yaml), &fromYAML); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(fromJSON, fromYAML) || fromJSON.Any() != test.any {
				t.Fatal("JSON and YAML source policies differ")
			}
			encoded, err := json.Marshal(fromJSON)
			if err != nil || string(encoded) != test.json {
				t.Fatalf("source policy roundtrip = %s, %v", encoded, err)
			}
		})
	}
	for _, input := range []string{`null`, `false`, `"all"`, `{"unknown":true}`, `[]`} {
		if err := json.Unmarshal([]byte(input), new(WebhookSources)); err == nil {
			t.Fatalf("accepted invalid JSON source policy: %s", input)
		}
	}
	for _, input := range []string{"false", "all", "unknown: true", "[]"} {
		if err := yaml.Unmarshal([]byte(input), new(WebhookSources)); err == nil {
			t.Fatalf("accepted invalid YAML source policy: %s", input)
		}
	}
	// YAML null bypasses custom unmarshaling; semantic validation rejects the
	// resulting empty policy rather than interpreting it as unrestricted access.
	var nullSources WebhookSources
	if err := yaml.Unmarshal([]byte("null"), &nullSources); err != nil {
		t.Fatal(err)
	}
	if err := ValidateWebhooks(Services{"api": {}}, map[string]Webhook{"payments": {Service: "api", Path: "/hooks/payments", AllowFrom: nullSources}}); err == nil {
		t.Fatal("YAML null granted webhook access")
	}
}

func TestWebhookPolicyValidation(t *testing.T) {
	services := Services{"api": {}}
	valid := Webhook{Service: "api", Path: "/hooks/payments", AllowFrom: WebhookSources{Providers: []string{"stripe"}}}
	for _, test := range []struct {
		name, want string
		change     func(*Webhook)
	}{
		{"valid", "", func(*Webhook) {}},
		{"missing service", "service is required", func(w *Webhook) { w.Service = "" }},
		{"unknown service", "not configured", func(w *Webhook) { w.Service = "missing" }},
		{"reserved path", "exact clean absolute path", func(w *Webhook) { w.Path = "/__tnl/hooks" }},
		{"encoded path", "exact clean absolute path", func(w *Webhook) { w.Path = "/hooks/%2Fpayments" }},
		{"unknown method", "supported HTTP method", func(w *Webhook) { w.Methods = []string{"CONNECT"} }},
		{"duplicate method", "supported HTTP method", func(w *Webhook) { w.Methods = []string{"POST", "POST"} }},
		{"empty sources", "allow_from requires", func(w *Webhook) { w.AllowFrom = WebhookSources{} }},
		{"unknown provider", "unknown or duplicate provider", func(w *Webhook) { w.AllowFrom.Providers = []string{"missing"} }},
		{"duplicate provider", "unknown or duplicate provider", func(w *Webhook) { w.AllowFrom.Providers = []string{"stripe", "stripe"} }},
		{"invalid IP", "invalid or duplicate IP", func(w *Webhook) { w.AllowFrom = WebhookSources{IPs: []string{"bad"}} }},
		{"duplicate IP", "invalid or duplicate IP", func(w *Webhook) { w.AllowFrom = WebhookSources{IPs: []string{"192.0.2.1", "192.0.2.1/32"}} }},
		{"noncanonical IP", "must be canonical", func(w *Webhook) { w.AllowFrom = WebhookSources{IPs: []string{"192.0.2.1/24"}} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			definition := valid
			test.change(&definition)
			err := ValidateWebhooks(services, map[string]Webhook{"payments": definition})
			if test.want == "" && err != nil || test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("validation = %v, want %q", err, test.want)
			}
		})
	}
	if err := ValidateWebhooks(services, map[string]Webhook{"first": valid, "second": valid}); err == nil || !strings.Contains(err.Error(), "path is also used") {
		t.Fatalf("duplicate path = %v", err)
	}
}

func TestWebhookFingerprintNormalizesDefaultsAndOrder(t *testing.T) {
	first := Webhook{Service: "api", Path: "/hooks/payments", AllowFrom: WebhookSources{Providers: []string{"stripe", "github"}, IPs: []string{"198.51.100.0/24", "192.0.2.0/24"}}}
	second := Webhook{Service: "api", Path: first.Path, Methods: []string{"POST"}, AllowFrom: WebhookSources{Providers: []string{"github", "stripe"}, IPs: []string{"192.0.2.0/24", "198.51.100.0/24"}}}
	before, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	_, left, err := first.DefinitionBytes()
	if err != nil {
		t.Fatal(err)
	}
	_, right, err := second.DefinitionBytes()
	if err != nil || left != right {
		t.Fatal("equivalent policies have different fingerprints")
	}
	after, err := json.Marshal(first)
	if err != nil || string(before) != string(after) {
		t.Fatal("fingerprinting mutated the caller's policy")
	}
	second.AllowFrom = AnyWebhookSources()
	_, changed, err := second.DefinitionBytes()
	if err != nil || changed == left {
		t.Fatal("changed source policy retained its old fingerprint")
	}
}
