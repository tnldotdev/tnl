package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWebhookPolicyValidation(t *testing.T) {
	services := Services{"api": {}}
	valid := Webhook{Service: "api", Path: "/hooks/payments", Provider: "stripe"}
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
		{"missing provider", "provider must be", func(w *Webhook) { w.Provider = "" }},
		{"unknown provider", "provider must be", func(w *Webhook) { w.Provider = "svix" }},
		{"old delivery", "fanout or selected", func(w *Webhook) { w.Delivery = "exclusive" }},
		{"empty override", "must not be empty", func(w *Webhook) { w.SourceIPs = []string{} }},
		{"invalid IP", "invalid or duplicate IP", func(w *Webhook) { w.SourceIPs = []string{"bad"} }},
		{"duplicate IP", "invalid or duplicate IP", func(w *Webhook) { w.SourceIPs = []string{"192.0.2.1", "192.0.2.1/32"} }},
		{"noncanonical IP", "must be canonical", func(w *Webhook) { w.SourceIPs = []string{"192.0.2.1/24"} }},
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

func TestWebhookDeliveryDefaultsAndFingerprint(t *testing.T) {
	for _, test := range []struct{ provider, want string }{
		{"stripe", "fanout"}, {"linear", "fanout"}, {"custom", "fanout"},
		{"discord", "selected"}, {"slack", "selected"}, {"twilio", "selected"},
		{"telegram", "selected"}, {"amazon-sns", "selected"},
	} {
		definition := Webhook{Provider: test.provider}
		if definition.DeliveryMode() != test.want {
			t.Fatalf("%s delivery = %q, want %q", test.provider, definition.DeliveryMode(), test.want)
		}
		definition.Delivery = "fanout"
		if definition.DeliveryMode() != "fanout" {
			t.Fatalf("explicit delivery for %s was ignored", test.provider)
		}
	}
	first := Webhook{Service: "api", Path: "/hooks/payments", Provider: "stripe", SourceIPs: []string{"198.51.100.0/24", "192.0.2.0/24"}}
	second := Webhook{Service: "api", Path: first.Path, Provider: "stripe", Delivery: "fanout", Methods: []string{"POST"}, SourceIPs: []string{"192.0.2.0/24", "198.51.100.0/24"}}
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
	second.SourceIPs = nil
	_, changed, err := second.DefinitionBytes()
	if err != nil || changed == left {
		t.Fatal("changed source policy retained its old fingerprint")
	}
}
