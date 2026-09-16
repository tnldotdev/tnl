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
	if err := tunnel.SetRoute(t.Context(), "route_0123456789abcdef0123456789abcdef", "route.example"); err != nil {
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
	if snapshot.SchemaVersion != 1 || snapshot.Summary.Ready != 1 || len(snapshot.Tunnels) != 1 ||
		snapshot.Tunnels[0].ID != tunnel.ID() {
		t.Fatalf("status snapshot = %#v", snapshot)
	}

	var payload map[string]any
	if err := json.Unmarshal(output.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	assertJSONKeys(t, payload, "schema_version", "observed_at", "summary", "tunnels")
	assertJSONKeys(t, payload["summary"].(map[string]any),
		"total", "starting", "provisioning", "ready", "draining", "stale")
	tunnels := payload["tunnels"].([]any)
	assertJSONKeys(t, tunnels[0].(map[string]any),
		"tunnel_id", "command", "state", "process_id", "server", "project", "service", "route_id", "route_version",
		"hostname", "public_url", "target", "started_at", "updated_at", "heartbeat_at", "lease_expires_at")
	if tunnels[0].(map[string]any)["route_version"] != float64(1) || tunnels[0].(map[string]any)["service"] != "web" {
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
		tunnel.ID(),
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
	assertJSONKeys(t, payload, "schema_version", "observed_at", "summary", "tunnels")
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
