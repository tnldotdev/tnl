package state

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func appliedWebhookConfiguration() config.TNL {
	return config.TNL{OAuth: true, Services: config.Services{"app": {Tunnel: &config.Tunnel{}}}, Webhooks: map[string]config.Webhook{
		"payments": {Service: "app", Path: "/hooks/payments", Provider: "stripe", Methods: []string{"POST", "GET"}, SourceIPs: []string{"198.51.100.0/24", "192.0.2.10"}},
		"chat":     {Service: "app", Path: "/hooks/chat", Provider: "slack"},
	}}
}

func TestNormalizeAppliedRootIntegrationsMatchAppRegistration(t *testing.T) {
	input := appliedWebhookConfiguration()
	before, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.ValidateWebhooks(input.Services, input.Webhooks); err != nil {
		t.Fatal(err)
	}
	for name, definition := range input.Webhooks {
		wire, hash, err := definition.DefinitionBytes()
		if err != nil {
			t.Fatal(err)
		}
		var normal config.Webhook
		if err := json.Unmarshal(wire, &normal); err != nil {
			t.Fatal(err)
		}
		if name == "payments" && normal.Delivery != "fanout" || name == "chat" && (normal.Delivery != "selected" || !slices.Equal(normal.Methods, []string{"POST"}) || normal.SourceIPs != nil) {
			t.Fatal("provider defaults lost")
		}
		repeated, repeatHash, err := normal.DefinitionBytes()
		if err != nil || repeatHash != hash || !bytes.Equal(repeated, wire) {
			t.Fatal("registration normal form changed on replay", err)
		}
	}
	after, err := json.Marshal(input)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatal("normalization changed caller declarations", err)
	}
	// OAuth intent stays in the app-owned project configuration. shared service
	// definitions cannot become a second desired-state or authorization document.
	input.OAuth = false
	changed, _ := json.Marshal(input)
	if bytes.Equal(changed, before) {
		t.Fatal("OAuth intent disappeared from local declaration")
	}
	if err := config.ValidateDocument(config.Document{Version: new(1), TNL: &config.TNL{OAuth: true}}); err != nil {
		t.Fatal("OAuth required an already running app", err)
	}
}

func TestNormalizeAppliedWebhooksRequireCurrentLocalPublicHTTPApp(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*config.TNL)
	}{
		{"unknown provider", func(c *config.TNL) { w := c.Webhooks["payments"]; w.Provider = "svix"; c.Webhooks["payments"] = w }},
		{"unknown service", func(c *config.TNL) { w := c.Webhooks["payments"]; w.Service = "missing"; c.Webhooks["payments"] = w }},
		{"missing service", func(c *config.TNL) { w := c.Webhooks["payments"]; w.Service = ""; c.Webhooks["payments"] = w }},
		{"private app", func(c *config.TNL) { s := c.Services["app"]; s.Tunnel = nil; c.Services["app"] = s }},
		{"private protocol", func(c *config.TNL) { c.Services["app"] = config.Service{Protocol: new("tcp")} }},
		{"remote handler", func(c *config.TNL) {
			c.Services["app"] = config.Service{Target: &config.ServiceTarget{Type: "address", Address: new(config.Target("http://eks.internal:3000"))}}
		}},
		{"duplicate path", func(c *config.TNL) {
			w := c.Webhooks["chat"]
			w.Path = c.Webhooks["payments"].Path
			c.Webhooks["chat"] = w
		}},
		{"encoded path", func(c *config.TNL) {
			w := c.Webhooks["payments"]
			w.Path = "/hooks/%2Fpayments"
			c.Webhooks["payments"] = w
		}},
		{"reserved path", func(c *config.TNL) { w := c.Webhooks["payments"]; w.Path = "/__tnl/hooks"; c.Webhooks["payments"] = w }},
		{"delivery", func(c *config.TNL) { w := c.Webhooks["payments"]; w.Delivery = "exclusive"; c.Webhooks["payments"] = w }},
		{"method", func(c *config.TNL) {
			w := c.Webhooks["payments"]
			w.Methods = []string{"CONNECT"}
			c.Webhooks["payments"] = w
		}},
		{"duplicate method", func(c *config.TNL) {
			w := c.Webhooks["payments"]
			w.Methods = []string{"POST", "POST"}
			c.Webhooks["payments"] = w
		}},
		{"empty source override", func(c *config.TNL) { w := c.Webhooks["payments"]; w.SourceIPs = []string{}; c.Webhooks["payments"] = w }},
		{"duplicate source", func(c *config.TNL) {
			w := c.Webhooks["payments"]
			w.SourceIPs = []string{"192.0.2.1", "192.0.2.1/32"}
			c.Webhooks["payments"] = w
		}},
		{"noncanonical source", func(c *config.TNL) {
			w := c.Webhooks["payments"]
			w.SourceIPs = []string{"192.0.2.1/24"}
			c.Webhooks["payments"] = w
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := appliedWebhookConfiguration()
			test.change(&c)
			if err := config.ValidateWebhooks(c.Services, c.Webhooks); err == nil {
				t.Fatal("invalid integration declaration accepted")
			}
		})
	}
}

func TestNormalizeAppliedWebhookLocalHTTPListeners(t *testing.T) {
	for _, target := range []string{"app", "http://localhost:3000", "compose:app:3000", "docker:app:3000"} {
		t.Run(target, func(t *testing.T) {
			c := appliedWebhookConfiguration()
			if _, err := normalizeLocalService("app", LocalServiceDeclaration{Target: target, PublicURL: &ProjectServicePublicURL{}}); err != nil {
				t.Fatal(err)
			}
			if err := config.ValidateWebhooks(c.Services, c.Webhooks); err != nil {
				t.Fatal(err)
			}
		})
	}
}
