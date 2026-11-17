package invocation

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/publisher/integrations"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationServiceUsesSelectedTeamDomainAndHostname(t *testing.T) {
	for _, hostname := range []string{"hooks.example.test", "hooks.member.example.test"} {
		t.Run(hostname, func(t *testing.T) {
			f := newServiceSetupFixture(t, hostname)
			for range 2 {
				cfg, saved, err := nativeIntegrationConfig(t.Context(), f.services, hostname, targetsyntax.WebhookIntegration, nil, integrationShutdown{})
				if err != nil {
					t.Fatal(err)
				}
				if cfg.ServiceID != saved.Id || saved.TeamId != f.services.teamID ||
					saved.DomainId == nil || *saved.DomainId != f.services.domainID ||
					saved.Endpoint == nil || saved.Endpoint.Hostname != hostname || saved.Endpoint.Port != 443 || !saved.Endpoint.Public ||
					saved.Source != nil || saved.Ephemeral || cfg.Target != "" ||
					f.declaration.Target != string(targetsyntax.WebhookIntegration) || f.declaration.Hostname == nil || *f.declaration.Hostname != hostname ||
					f.declaration.DomainId == nil || *f.declaration.DomainId != f.services.domainID {
					t.Fatal("integration changed the selected ordinary service placement or saved a private target", cfg, saved, f.declaration)
				}
			}
			if f.creates != 1 || f.enrollments != 1 {
				t.Fatal("unchanged integration setup replaced its saved service or publisher grant", f.creates, f.enrollments)
			}
		})
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
	output := &Presentation{Progress: func(Progress) error { return cause }}
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
	group := clientstate.IntegrationScope{PrimaryProjectRoot: t.TempDir(), Namespace: "member.example.test"}
	const hostname = "hooks.member.example.test"
	if _, err := state.Server(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: server, ServiceID: id, Target: "3000", Project: t.TempDir(), Service: "api", IntegrationScope: group,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	definition := config.Webhook{Service: "api", Path: "/hooks/event", Provider: "slack", Delivery: "selected"}
	encoded, digest, err := integrations.DefinitionBytes(definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.RegisterWebhookEndpoint(t.Context(), "event", encoded); err != nil {
		t.Fatal(err)
	}
	fanout := config.Webhook{Service: "api", Path: "/hooks/fanout", Provider: "custom"}
	fanoutBytes, _, err := integrations.DefinitionBytes(fanout)
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
	if err := tunnel.SetProvisioning(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetReady(t.Context(), "https://api.member.example.test", 1); err != nil {
		t.Fatal(err)
	}
	integrationID, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	integration, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish,
		Server: server, ServiceID: integrationID, Target: "3000", Project: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer integration.Finish(context.Background(), nil)
	prepared := controlv1.ServiceRunPreparation{ServiceId: integrationID, Hostname: hostname, RunNumber: 1}
	if err := integration.SetProvisioning(t.Context(), uint64(prepared.RunNumber)); err != nil {
		t.Fatal(err)
	}
	if err := integration.SetReady(t.Context(), "https://"+prepared.Hostname, uint64(prepared.RunNumber)); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkIntegrationURLReady(t.Context(), server, prepared.Hostname, "owner", prepared.ServiceId, uint64(prepared.RunNumber)); err != nil {
		t.Fatal(err)
	}
	if mode := readyWebhookDelivery(t.Context(), state, server, group, hostname, map[string]config.Webhook{"fanout": fanout}); mode != "fanout" {
		t.Fatalf("ready fanout endpoint = %q", mode)
	}
	if mode := readyWebhookDelivery(t.Context(), state, server, group, hostname, definitions); mode != "" {
		t.Fatalf("exclusive endpoint without owner reported ready: %q", mode)
	}
	if err := state.ClaimWebhookReceiver(t.Context(), server, group, "event", tunnel.ID(), digest, false); err != nil {
		t.Fatal(err)
	}
	if mode := readyWebhookDelivery(t.Context(), state, server, group, hostname, definitions); mode != "selected" {
		t.Fatalf("ready exclusive endpoint = %q", mode)
	}
	if err := tunnel.SetProvisioning(t.Context(), 2); err != nil {
		t.Fatal(err)
	}
	if mode := readyWebhookDelivery(t.Context(), state, server, group, hostname, definitions); mode != "" {
		t.Fatalf("reprovisioning receiver reported ready: %q", mode)
	}
}
