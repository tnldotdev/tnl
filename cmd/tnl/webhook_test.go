package main

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/integrationurls"
	"github.com/tnldotdev/tnl/internal/projectconfig"
)

func TestWebhookCommandRequiresProjectConfiguration(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	err := run(t.Context(), []string{"--no-config", "webhook", "use", "stripe", "--state-dir", root}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "project configuration") {
		t.Fatalf("webhook use without a project = %v", err)
	}
}

func TestExclusiveWebhookCommandClaimsOnlyCurrentReadyWorktree(t *testing.T) {
	projectRoot := t.TempDir()
	stateRoot := filepath.Join(t.TempDir(), "state")
	state, err := clientstate.Open(t.Context(), stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	const server, hooks = "https://control.example.test", "hooks.project.example.test"
	group := projectRoot + "\x00project.example.test"
	if _, err := state.IntegrationURLHostname(t.Context(), server, projectRoot, "project.example.test", "hooks", hooks); err != nil {
		t.Fatal(err)
	}
	tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: server, Project: projectRoot, Service: "api",
		Target: "3000", IntegrationGroup: group,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tunnel.Finish(t.Context(), nil) })
	if err := tunnel.SetPublicURL(t.Context(), "url_0123456789abcdefghijkl", "api.project.example.test"); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetProvisioning(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetReady(t.Context(), "https://api.project.example.test", 1); err != nil {
		t.Fatal(err)
	}
	definition := config.Webhook{Service: "api", Path: "/hooks/stripe", Delivery: "exclusive", AllowFrom: config.WebhookSources{IPs: []string{"192.0.2.0/24"}}}
	encoded, _, err := integrationurls.DefinitionBytes(definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.RegisterWebhookEndpoint(t.Context(), "stripe", encoded); err != nil {
		t.Fatal(err)
	}
	project := projectConfiguration{Project: projectconfig.Project{
		Root: projectRoot, Selection: projectconfig.Selection{Path: filepath.Join(projectRoot, "tnl.json")},
		Config: config.TNL{Services: config.Services{"api": {}}, Webhooks: map[string]config.Webhook{"stripe": definition}},
	}}
	command := webhookChoiceCommand{remoteFlags: remoteFlags{ServerURL: server, StateDir: stateRoot}, Endpoint: "stripe"}
	var output bytes.Buffer
	if err := runWebhookChoice(t.Context(), command, project, true, false, &output); err != nil ||
		!strings.Contains(output.String(), "https://"+hooks+"/hooks/stripe") {
		t.Fatalf("claim frame: %s, error %v", output.String(), err)
	}
	otherRoot := t.TempDir()
	other, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: server, Project: otherRoot, Service: "api",
		Target: "4000", IntegrationGroup: group,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Finish(t.Context(), nil) })
	if err := other.SetPublicURL(t.Context(), "url_abcdefghijklmnopqrstuv", "api-feature.project.example.test"); err != nil {
		t.Fatal(err)
	}
	if err := other.SetProvisioning(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if err := other.SetReady(t.Context(), "https://api-feature.project.example.test", 1); err != nil {
		t.Fatal(err)
	}
	if err := other.RegisterWebhookEndpoint(t.Context(), "stripe", encoded); err != nil {
		t.Fatal(err)
	}
	otherProject := projectConfiguration{Project: projectconfig.Project{
		Root: otherRoot, Selection: projectconfig.Selection{Path: filepath.Join(otherRoot, "tnl.json")}, Config: project.Config,
	}}
	if err := runWebhookChoice(t.Context(), command, otherProject, true, false, &output); err == nil {
		t.Fatal("ordinary selection displaced another running tunnel")
	} else if reason, ok := failure.ReasonOf(err); !ok || reason != failure.WebhookOwned || !errors.Is(err, clientstate.ErrWebhookOwned) {
		t.Fatalf("ownership conflict reason = %v", err)
	}
	if err := runWebhookChoice(t.Context(), command, otherProject, true, true, &output); err != nil {
		t.Fatalf("force selection from ready worktree: %v", err)
	}
	if err := runWebhookChoice(t.Context(), command, project, false, false, &output); err == nil {
		t.Fatal("previous owner released another worktree's selection")
	} else if reason, ok := failure.ReasonOf(err); !ok || reason != failure.WebhookNotSelected || !errors.Is(err, clientstate.ErrWebhookNotSelected) {
		t.Fatalf("release conflict reason = %v", err)
	}
	if err := runWebhookChoice(t.Context(), command, otherProject, false, false, &output); err != nil {
		t.Fatalf("release selected worktree: %v", err)
	}
}
