package controlstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func appliedWebhookConfiguration() ProjectConfiguration {
	return ProjectConfiguration{OAuth: true, Services: map[string]ProjectServiceConfiguration{"app": {Target: "app", PublicURL: &ProjectServicePublicURL{}}}, Webhooks: map[string]ProjectWebhook{
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
	normal, hash, err := NormalizeProjectConfiguration(input)
	if err != nil {
		t.Fatal(err)
	}
	if !normal.OAuth || normal.Webhooks["payments"].Delivery != "fanout" || normal.Webhooks["chat"].Delivery != "selected" || !slices.Equal(normal.Webhooks["chat"].Methods, []string{"POST"}) || normal.Webhooks["chat"].SourceIPs != nil {
		t.Fatal("integration normal form dropped root values or provider defaults")
	}
	w := input.Webhooks["payments"]
	wire, _, err := (config.Webhook{Service: w.Service, Path: w.Path, Provider: w.Provider, Delivery: w.Delivery, Methods: w.Methods, SourceIPs: w.SourceIPs}).DefinitionBytes()
	if err != nil {
		t.Fatal(err)
	}
	stored, err := json.Marshal(normal.Webhooks["payments"])
	if err != nil || !bytes.Equal(stored, wire) {
		t.Fatal("applied definition does not match the app registration normal form", err)
	}
	after, err := json.Marshal(input)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatal("normalization changed caller webhook declarations", err)
	}
	_, repeat, err := NormalizeProjectConfiguration(normal)
	if err != nil || repeat != hash {
		t.Fatal("normalized integration replay changed its hash", err)
	}
	normal.OAuth = false
	_, changed, err := NormalizeProjectConfiguration(normal)
	if err != nil || changed == hash {
		t.Fatal("OAuth-only change did not change the desired hash", err)
	}
	if _, _, err = NormalizeProjectConfiguration(ProjectConfiguration{OAuth: true}); err != nil {
		t.Fatal("OAuth intent required an already-running app", err)
	}
}

func TestNormalizeAppliedWebhooksRequireCurrentLocalPublicHTTPApp(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*ProjectConfiguration)
	}{
		{"unknown provider", func(c *ProjectConfiguration) {
			w := c.Webhooks["payments"]
			w.Provider = "svix"
			c.Webhooks["payments"] = w
		}},
		{"unknown service", func(c *ProjectConfiguration) {
			w := c.Webhooks["payments"]
			w.Service = "missing"
			c.Webhooks["payments"] = w
		}},
		{"missing service", func(c *ProjectConfiguration) { w := c.Webhooks["payments"]; w.Service = ""; c.Webhooks["payments"] = w }},
		{"private app", func(c *ProjectConfiguration) { s := c.Services["app"]; s.PublicURL = nil; c.Services["app"] = s }},
		{"private protocol", func(c *ProjectConfiguration) {
			c.Services["app"] = ProjectServiceConfiguration{Protocol: "tcp", Target: "db.internal:5432"}
		}},
		{"remote handler", func(c *ProjectConfiguration) {
			id, err := opaqueid.New(opaqueid.DomainPrefix)
			if err != nil {
				t.Fatal(err)
			}
			c.Publishers = map[string]ProjectPublisherGroup{"production": {}}
			c.Services["app"] = ProjectServiceConfiguration{Publisher: "production", Target: "http://eks.internal:3000", PublicURL: &ProjectServicePublicURL{DomainID: id}}
		}},
		{"duplicate path", func(c *ProjectConfiguration) {
			w := c.Webhooks["chat"]
			w.Path = c.Webhooks["payments"].Path
			c.Webhooks["chat"] = w
		}},
		{"encoded path", func(c *ProjectConfiguration) {
			w := c.Webhooks["payments"]
			w.Path = "/hooks/%2Fpayments"
			c.Webhooks["payments"] = w
		}},
		{"reserved path", func(c *ProjectConfiguration) {
			w := c.Webhooks["payments"]
			w.Path = "/__tnl/hooks"
			c.Webhooks["payments"] = w
		}},
		{"delivery", func(c *ProjectConfiguration) {
			w := c.Webhooks["payments"]
			w.Delivery = "exclusive"
			c.Webhooks["payments"] = w
		}},
		{"method", func(c *ProjectConfiguration) {
			w := c.Webhooks["payments"]
			w.Methods = []string{"CONNECT"}
			c.Webhooks["payments"] = w
		}},
		{"duplicate method", func(c *ProjectConfiguration) {
			w := c.Webhooks["payments"]
			w.Methods = []string{"POST", "POST"}
			c.Webhooks["payments"] = w
		}},
		{"empty source override", func(c *ProjectConfiguration) {
			w := c.Webhooks["payments"]
			w.SourceIPs = []string{}
			c.Webhooks["payments"] = w
		}},
		{"duplicate source", func(c *ProjectConfiguration) {
			w := c.Webhooks["payments"]
			w.SourceIPs = []string{"192.0.2.1", "192.0.2.1/32"}
			c.Webhooks["payments"] = w
		}},
		{"noncanonical source", func(c *ProjectConfiguration) {
			w := c.Webhooks["payments"]
			w.SourceIPs = []string{"192.0.2.1/24"}
			c.Webhooks["payments"] = w
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := appliedWebhookConfiguration()
			test.change(&c)
			if _, _, err := NormalizeProjectConfiguration(c); !errors.Is(err, ErrProjectConfigurationInvalid) {
				t.Fatal("invalid integration declaration was accepted", err)
			}
		})
	}
}

func TestNormalizeAppliedWebhookLocalHTTPListeners(t *testing.T) {
	for _, target := range []string{"app", "http://localhost:3000", "compose:app:3000", "docker:app:3000"} {
		t.Run(target, func(t *testing.T) {
			c := appliedWebhookConfiguration()
			s := c.Services["app"]
			s.Target = target
			c.Services["app"] = s
			if _, _, err := NormalizeProjectConfiguration(c); err != nil {
				t.Fatal(err)
			}
		})
	}
}
