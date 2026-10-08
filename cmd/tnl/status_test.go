package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/integrationurls"
)

func TestStatusJSONUsesSharedTunnelSnapshot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	state, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: "https://server.example", Target: "3000",
		Project: t.TempDir(), Service: "web",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	if err := tunnel.SetPublicURL(t.Context(), "url_0123456789abcdefghijkl", "route.example"); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetReady(t.Context(), "https://route.example", 1); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runStatus(t.Context(), statusCommand{Output: "json", StateDir: root, All: true}, &output); err != nil {
		t.Fatal(err)
	}
	var snapshot clientstate.TunnelSnapshot
	if err := json.Unmarshal(output.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.SchemaVersion != 2 || snapshot.Summary.Ready != 1 || len(snapshot.Tunnels) != 1 || len(snapshot.IntegrationURLs) != 0 ||
		snapshot.Tunnels[0].ID != tunnel.ID() {
		t.Fatalf("status snapshot = %#v", snapshot)
	}

	var payload map[string]any
	if err := json.Unmarshal(output.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	assertJSONKeys(t, payload, "schema_version", "observed_at", "summary", "tunnels", "integration_urls")
	assertJSONKeys(t, payload["summary"].(map[string]any),
		"total", "starting", "provisioning", "ready", "draining", "stale")
	tunnels := payload["tunnels"].([]any)
	assertJSONKeys(t, tunnels[0].(map[string]any),
		"tunnel_id", "command", "state", "process_id", "server", "project", "service", "public_url_id", "publish_run_number",
		"hostname", "public_url", "target", "started_at", "updated_at", "heartbeat_at", "lease_expires_at")
	if tunnels[0].(map[string]any)["publish_run_number"] != float64(1) || tunnels[0].(map[string]any)["service"] != "web" {
		t.Fatalf("tunnel = %v", tunnels[0])
	}

	output.Reset()
	if err := runStatus(t.Context(), statusCommand{Output: "human", StateDir: root, All: true}, &output); err != nil {
		t.Fatal(err)
	}
	human := output.String()
	for _, fragment := range []string{
		"+--[ tnl status ]-- 1 local tunnel ",
		"|-- ready ",
		"https://route.example",
		"tunnel              " + tunnel.ID()[:len(tunnel.ID())-1],
		"+-- 1 ready ",
	} {
		if !strings.Contains(human, fragment) {
			t.Fatalf("human status does not contain %q:\n%s", fragment, human)
		}
	}
}

func TestStatusJSONStartingAdHocTunnelOmitsUnassignedFields(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	state, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandDev, Server: "https://server.example", Project: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	var output bytes.Buffer
	if err := runStatus(t.Context(), statusCommand{Output: "json", StateDir: root, All: true}, &output); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		t.Fatal(err)
	}
	assertJSONKeys(t, payload, "schema_version", "observed_at", "summary", "tunnels", "integration_urls")
	tunnels, ok := payload["tunnels"].([]any)
	if !ok || len(tunnels) != 1 {
		t.Fatalf("tunnels = %#v", payload["tunnels"])
	}
	wire, ok := tunnels[0].(map[string]any)
	if !ok {
		t.Fatalf("tunnel = %#v", tunnels[0])
	}
	assertJSONKeys(t, wire, "tunnel_id", "command", "state", "process_id", "server", "project", "started_at", "updated_at", "heartbeat_at", "lease_expires_at")
	if wire["tunnel_id"] != tunnel.ID() || wire["state"] != "starting" || wire["command"] != "dev" {
		t.Fatalf("tunnel = %#v", wire)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("trailing output = %v, %v", extra, err)
	}
}

func assertJSONKeys(t *testing.T, value map[string]any, keys ...string) {
	t.Helper()
	if len(value) != len(keys) {
		t.Fatalf("JSON keys = %v, want %v", value, keys)
	}
	for _, key := range keys {
		if _, ok := value[key]; !ok {
			t.Fatalf("JSON object %v is missing key %q", value, key)
		}
	}
}

func TestStatusHumanHandlesEmptyState(t *testing.T) {
	var output bytes.Buffer
	if err := runStatus(t.Context(), statusCommand{
		Output: "human", StateDir: filepath.Join(t.TempDir(), "state"),
	}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output.String(), "+--[ tnl status ]-- no local tunnels ") ||
		!strings.Contains(output.String(), "tnl publish 3000") {
		t.Fatalf("status output = %q", output.String())
	}
}

func TestStatusDefaultsToCurrentProjectAndAllIsExplicit(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	state, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	currentProject, otherProject := t.TempDir(), t.TempDir()
	for _, project := range []string{currentProject, otherProject} {
		tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
			Command: clientstate.TunnelCommandDev, Server: "https://server.example", Project: project,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer tunnel.Finish(context.Background(), nil)
	}
	var output bytes.Buffer
	if err := runStatus(t.Context(), statusCommand{
		Output: "json", StateDir: root, Project: currentProject,
	}, &output); err != nil {
		t.Fatal(err)
	}
	var contextual clientstate.TunnelSnapshot
	if err := json.Unmarshal(output.Bytes(), &contextual); err != nil {
		t.Fatal(err)
	}
	if len(contextual.Tunnels) != 1 || contextual.Tunnels[0].Project != currentProject {
		t.Fatalf("contextual snapshot = %#v", contextual)
	}
	output.Reset()
	if err := runStatus(t.Context(), statusCommand{Output: "json", StateDir: root, All: true}, &output); err != nil {
		t.Fatal(err)
	}
	var all clientstate.TunnelSnapshot
	if err := json.Unmarshal(output.Bytes(), &all); err != nil {
		t.Fatal(err)
	}
	if len(all.Tunnels) != 2 {
		t.Fatalf("all snapshot = %#v", all)
	}
}

func TestStatusShowsIntegrationURLSubscribersAndExclusiveOwner(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	state, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	const server, namespace, key = "https://control.example.test", "member.example.test", "/projects/shop"
	group := key + "\x00" + namespace
	for purpose, hostname := range map[string]string{
		"oauth": "oauth-shop-ab1234.member.example.test",
		"hooks": "hooks-shop-ab1234.member.example.test",
	} {
		if _, err := state.IntegrationURLHostname(t.Context(), server, key, namespace, purpose, hostname); err != nil {
			t.Fatal(err)
		}
		if err := state.MarkIntegrationURLReady(t.Context(), server, hostname, "publisher"); err != nil {
			t.Fatal(err)
		}
	}
	definition := config.Webhook{
		Service: "api", Path: "/hooks/payments", Delivery: "exclusive",
		AllowFrom: config.WebhookSources{IPs: []string{"192.0.2.0/24"}},
	}
	encoded, digest, err := integrationurls.DefinitionBytes(definition)
	if err != nil {
		t.Fatal(err)
	}
	primary, linked := t.TempDir(), t.TempDir()
	var tunnels []*clientstate.Tunnel
	for index, project := range []string{primary, linked} {
		hostname := "api-main.member.example.test"
		id := "url_0123456789abcdefghijkl"
		if index == 1 {
			hostname = "api-feature.member.example.test"
			id = "url_abcdefghijklmnopqrstuv"
		}
		tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
			Command: clientstate.TunnelCommandPublish, Server: server, Project: project,
			Service: "api", Target: "3000", IntegrationGroup: group,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer tunnel.Finish(context.Background(), nil)
		if err := tunnel.SetPublicURL(t.Context(), id, hostname); err != nil {
			t.Fatal(err)
		}
		if err := tunnel.SetProvisioning(t.Context(), 1); err != nil {
			t.Fatal(err)
		}
		if err := tunnel.SetReady(t.Context(), "https://"+hostname, 1); err != nil {
			t.Fatal(err)
		}
		if err := tunnel.RegisterWebhookEndpoint(t.Context(), "payments", encoded); err != nil {
			t.Fatal(err)
		}
		tunnels = append(tunnels, tunnel)
	}
	if err := state.ClaimWebhookReceiver(t.Context(), server, group, "payments", tunnels[0].ID(), digest, false); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	read := func() (clientstate.TunnelSnapshot, string) {
		t.Helper()
		output.Reset()
		if err := runStatus(t.Context(), statusCommand{Output: "json", StateDir: root, Project: primary}, &output); err != nil {
			t.Fatal(err)
		}
		var snapshot clientstate.TunnelSnapshot
		if err := json.Unmarshal(output.Bytes(), &snapshot); err != nil {
			t.Fatal(err)
		}
		return snapshot, output.String()
	}
	snapshot, wire := read()
	if snapshot.SchemaVersion != 2 || len(snapshot.Tunnels) != 1 || len(snapshot.IntegrationURLs) != 2 {
		t.Fatalf("project status = %#v", snapshot)
	}
	var hooks *clientstate.IntegrationURLInfo
	for i := range snapshot.IntegrationURLs {
		item := &snapshot.IntegrationURLs[i]
		if item.State != "ready" {
			t.Fatalf("ready publisher = %#v", item)
		}
		if item.Kind == "webhooks" {
			hooks = item
		}
	}
	if hooks == nil || len(hooks.Endpoints) != 1 || hooks.Endpoints[0].State != "ready" ||
		len(hooks.Endpoints[0].ReadyReceivers) != 2 || hooks.Endpoints[0].Owner == nil || hooks.Endpoints[0].Owner.TunnelID != tunnels[0].ID() {
		t.Fatalf("exclusive worktree status = %#v", hooks)
	}
	var envelope map[string]any
	if err := json.Unmarshal([]byte(wire), &envelope); err != nil {
		t.Fatal(err)
	}
	assertJSONKeys(t, envelope, "schema_version", "observed_at", "summary", "tunnels", "integration_urls")
	for _, raw := range envelope["integration_urls"].([]any) {
		url := raw.(map[string]any)
		if url["kind"] != "webhooks" {
			assertJSONKeys(t, url, "kind", "server", "hostname", "public_url", "state")
			continue
		}
		assertJSONKeys(t, url, "kind", "server", "hostname", "public_url", "state", "endpoints")
		endpoint := url["endpoints"].([]any)[0].(map[string]any)
		assertJSONKeys(t, endpoint, "name", "service", "path", "url", "delivery", "state", "ready_receivers", "owner")
		assertJSONKeys(t, endpoint["owner"].(map[string]any), "tunnel_id", "project", "service", "public_url", "state")
	}
	if err := state.SaveOAuthCallback(t.Context(), server, "oauth-shop-ab1234.member.example.test", group, "secret-oauth-state", tunnels[0].ID(), "/callback", "", "url_0123456789abcdefghijkl", 1); err != nil {
		t.Fatal(err)
	}
	if _, wire := read(); strings.Contains(wire, "secret-oauth-state") {
		t.Fatal("status exposed OAuth state")
	}
	if err := tunnels[0].SetProvisioning(t.Context(), 2); err != nil {
		t.Fatal(err)
	}
	snapshot, _ = read()
	for _, item := range snapshot.IntegrationURLs {
		if item.Kind == "webhooks" {
			endpoint := item.Endpoints[0]
			if endpoint.Reason != failure.WebhookOwnerUnready || endpoint.Owner == nil || endpoint.Owner.State != "provisioning" || len(endpoint.ReadyReceivers) != 1 {
				t.Fatalf("temporarily unready owner = %#v", endpoint)
			}
		}
	}
	if err := state.ClaimWebhookReceiver(t.Context(), server, group, "payments", tunnels[1].ID(), digest, true); err != nil {
		t.Fatal(err)
	}
	snapshot, _ = read()
	for _, item := range snapshot.IntegrationURLs {
		if item.Kind == "webhooks" && (item.Endpoints[0].State != "ready" || item.Endpoints[0].Owner == nil || item.Endpoints[0].Owner.TunnelID != tunnels[1].ID()) {
			t.Fatalf("forced handoff status = %#v", item.Endpoints[0])
		}
	}
	output.Reset()
	if err := runStatus(t.Context(), statusCommand{Output: "human", StateDir: root, Project: primary}, &output); err != nil ||
		!strings.Contains(output.String(), "ready receivers") || !strings.Contains(output.String(), "api-feature.member.example.test") {
		t.Fatalf("human integration status = %q, %v", output.String(), err)
	}
}
