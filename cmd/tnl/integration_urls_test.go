package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/integrationurls"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationURLUsesTheSelectedPublicURLScope(t *testing.T) {
	for _, scope := range []controlv1.PublicURLScope{controlv1.Shared, controlv1.Member} {
		config := integrationURLConfig(publisherServices{publicURLScope: scope}, "hooks.example.test", controlv1.Webhooks)
		if config.PublicURLScope != scope || config.Purpose != controlv1.Webhooks || config.Hostname != "hooks.example.test" || config.Ephemeral {
			t.Fatalf("integration URL scope %q produced %#v", scope, config)
		}
	}
}

func TestIntegrationURLProgressFailureStopsTheTunnelWithItsCause(t *testing.T) {
	state, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: "https://control.example.test", Target: "3000", Project: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	cause := errors.New("private output destination failed with secret")
	output := &publishOutput{command: "tnl publish", stderr: errorWriter{err: cause}}
	reportIntegrationURL(tunnel, output, "oauth ready", "", clioutput.Text("https://oauth.example.test"))
	select {
	case <-tunnel.Context().Done():
	default:
		t.Fatal("integration URL output failure did not stop the tunnel")
	}
	reported := context.Cause(tunnel.Context())
	if reason, ok := failure.ReasonOf(reported); !ok || reason != failure.OutputUnavailable || !errors.Is(reported, cause) {
		t.Fatalf("integration URL output cause = %v", reported)
	}
	definition, _ := failure.DefinitionFor(failure.OutputUnavailable)
	if definition.Message == "" || definition.Action == "" {
		t.Fatal("output error did not have safe presentation")
	}
}

func TestWebhookReadyTelemetryRequiresPublishedURLAndSelectedReceiver(t *testing.T) {
	state, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	const server = "https://control.example.test"
	const group = "project\x00member.example.test"
	const hostname = "hooks.member.example.test"
	if _, err := state.Server(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: server, Target: "3000", Project: t.TempDir(), Service: "api", IntegrationGroup: group,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	definition := config.Webhook{Service: "api", Path: "/hooks/event", Delivery: "exclusive", AllowFrom: config.AnyWebhookSources()}
	encoded, digest, err := integrationurls.DefinitionBytes(definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.RegisterWebhookEndpoint(t.Context(), "event", encoded); err != nil {
		t.Fatal(err)
	}
	fanout := config.Webhook{Service: "api", Path: "/hooks/fanout", AllowFrom: config.AnyWebhookSources()}
	fanoutBytes, _, err := integrationurls.DefinitionBytes(fanout)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.RegisterWebhookEndpoint(t.Context(), "fanout", fanoutBytes); err != nil {
		t.Fatal(err)
	}
	definitions := map[string]config.Webhook{"event": definition}
	if mode := readyWebhookDelivery(t.Context(), state, server, group, hostname, definitions); mode != "" {
		t.Fatalf("unpublished URL reported ready: %q", mode)
	}
	id, err := opaqueid.New(opaqueid.PublicURLPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetPublicURL(t.Context(), id, "api.member.example.test"); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetProvisioning(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetReady(t.Context(), "https://api.member.example.test", 1); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkIntegrationURLReady(t.Context(), server, hostname, "owner"); err != nil {
		t.Fatal(err)
	}
	if mode := readyWebhookDelivery(t.Context(), state, server, group, hostname, map[string]config.Webhook{"fanout": fanout}); mode != telemetryFanout {
		t.Fatalf("ready fanout endpoint = %q", mode)
	}
	if mode := readyWebhookDelivery(t.Context(), state, server, group, hostname, definitions); mode != "" {
		t.Fatalf("exclusive endpoint without owner reported ready: %q", mode)
	}
	if err := state.ClaimWebhookReceiver(t.Context(), server, group, "event", tunnel.ID(), digest, false); err != nil {
		t.Fatal(err)
	}
	if mode := readyWebhookDelivery(t.Context(), state, server, group, hostname, definitions); mode != telemetryExclusive {
		t.Fatalf("ready exclusive endpoint = %q", mode)
	}
	if err := tunnel.SetProvisioning(t.Context(), 2); err != nil {
		t.Fatal(err)
	}
	if mode := readyWebhookDelivery(t.Context(), state, server, group, hostname, definitions); mode != "" {
		t.Fatalf("reprovisioning receiver reported ready: %q", mode)
	}
}
