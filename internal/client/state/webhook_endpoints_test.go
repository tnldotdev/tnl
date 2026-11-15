package state

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
	const server = "https://control.example.test"
	group := IntegrationScope{PrimaryProjectRoot: "/projects/shop", Namespace: "member.example.test"}
	var tunnels []*Tunnel
	for _, service := range []string{"web", "api"} {
		tunnel, err := state.BeginTunnel(t.Context(), BeginTunnelOptions{Command: TunnelCommandPublish, Server: server, Target: "3000", Project: t.TempDir(), Service: service, IntegrationScope: group})
		if err != nil {
			t.Fatal(err)
		}
		tunnels = append(tunnels, tunnel)
		t.Cleanup(func() { _ = tunnel.Finish(t.Context(), nil) })
	}
	definition := config.Webhook{Service: "api", Path: "/hooks/stripe", Provider: "stripe"}
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
	definition.Provider = "custom"
	different, err := json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnels[1].RegisterWebhookEndpoint(t.Context(), "stripe", different); !errors.Is(err, ErrWebhookPolicyConflict) {
		t.Fatalf("another policy replaced the first: %v", err)
	}
	definition.Provider = "github"
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

func TestAliasAndWebhookRequireServiceIdentityEvenWithAnAddress(t *testing.T) {
	state, _ := aliasTestDatabase(t)
	scope := aliasTestScope(t)
	group := IntegrationScope{PrimaryProjectRoot: scope.ProjectKey, Namespace: scope.Namespace}
	tunnel, err := state.BeginTunnel(t.Context(), BeginTunnelOptions{
		Command: TunnelCommandPublish, Server: scope.Server, Project: scope.ProjectKey,
		Service: "api", Target: "3000", IntegrationScope: group,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tunnel.Finish(t.Context(), nil) })
	if err := tunnel.SetReady(t.Context(), "https://api."+scope.Namespace, 1); err != nil {
		t.Fatal(err)
	}
	definition, digest, err := (config.Webhook{Service: "api", Path: "/hook", Provider: "custom", Delivery: "selected"}).DefinitionBytes()
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.RegisterWebhookEndpoint(t.Context(), "event", definition); err != nil {
		t.Fatal(err)
	}
	selection, err := state.RegisterAlias(t.Context(), AliasRegistration{
		Scope: scope, Hostname: "review." + scope.Namespace, Service: "api", TunnelID: tunnel.ID(),
		IntegrationScope: group, Fingerprint: digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.AliasCandidate(t.Context(), selection.ID); !errors.Is(err, ErrAliasReceiverUnavailable) {
		t.Fatalf("address without a service identity became an alias receiver: %v", err)
	}
	receivers, err := state.WebhookReceivers(t.Context(), scope.Server, group, "event", digest)
	if err != nil || len(receivers) != 0 {
		t.Fatalf("address without a service identity became a webhook receiver: %+v, %v", receivers, err)
	}
	if err := state.ClaimWebhookReceiver(t.Context(), scope.Server, group, "event", tunnel.ID(), digest, true); !errors.Is(err, ErrWebhookReceiverUnavailable) {
		t.Fatalf("forced webhook selection admitted an address without a service identity: %v", err)
	}
}
