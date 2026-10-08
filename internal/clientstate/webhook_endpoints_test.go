package clientstate

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestWebhookRegistrationDoesNotReplaceOtherWorktreePolicies(t *testing.T) {
	state, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	const server, group = "https://control.example.test", "/projects/shop\x00member.example.test"
	var tunnels []*Tunnel
	for _, service := range []string{"web", "api"} {
		tunnel, err := state.BeginTunnel(t.Context(), BeginTunnelOptions{Command: TunnelCommandPublish, Server: server, Target: "3000", Project: t.TempDir(), Service: service, IntegrationGroup: group})
		if err != nil {
			t.Fatal(err)
		}
		tunnels = append(tunnels, tunnel)
		t.Cleanup(func() { _ = tunnel.Finish(t.Context(), nil) })
	}
	definition := config.Webhook{Service: "api", Path: "/hooks/stripe", AllowFrom: config.WebhookSources{Providers: []string{"stripe"}}}
	encoded, err := json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	for _, tunnel := range tunnels {
		if err := tunnel.RegisterWebhookEndpoint(t.Context(), "stripe", encoded); err != nil {
			t.Fatal(err)
		}
	}
	definitions, err := state.ActiveWebhookDefinitions(t.Context(), server, group)
	if err != nil || len(definitions) != 1 {
		t.Fatalf("merged definitions: %v", err)
	}
	definition.AllowFrom = config.AnyWebhookSources()
	different, err := json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnels[1].RegisterWebhookEndpoint(t.Context(), "stripe", different); !errors.Is(err, ErrWebhookPolicyConflict) {
		t.Fatalf("another policy replaced the first: %v", err)
	}
	definition.AllowFrom = config.WebhookSources{Providers: []string{"github"}}
	duplicatePath, err := json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnels[1].RegisterWebhookEndpoint(t.Context(), "github", duplicatePath); !errors.Is(err, ErrWebhookPolicyConflict) {
		t.Fatalf("duplicate path accepted: %v", err)
	}
	definition.Path = "/hooks/github"
	second, err := json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnels[1].RegisterWebhookEndpoint(t.Context(), "github", second); err != nil {
		t.Fatal(err)
	}
	definitions, err = state.ActiveWebhookDefinitions(t.Context(), server, group)
	if err != nil || len(definitions) != 2 {
		t.Fatalf("new endpoint did not join the existing group: %v", err)
	}
	if err := tunnels[1].Finish(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	definitions, err = state.ActiveWebhookDefinitions(t.Context(), server, group)
	if err != nil || len(definitions) != 1 {
		t.Fatalf("stopped tunnel still supplies declarations: %v", err)
	}
}
