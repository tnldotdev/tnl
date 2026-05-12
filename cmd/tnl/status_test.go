package main

import (
	"bytes"
	"context"
	"encoding/json"
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
	tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: "https://server.example", Target: "3000",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetRoute(t.Context(), "route_0123456789abcdef0123456789abcdef", "route.example"); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetReady(t.Context(), "https://route.example", 1); err != nil {
		t.Fatal(err)
	}
	defer func() {
		tunnel.Finish(context.Background(), nil)
		state.Close()
	}()

	var output bytes.Buffer
	if err := runStatus(t.Context(), statusCommand{Output: "json", StateDir: root}, &output); err != nil {
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
		"tunnel_id", "command", "state", "process_id", "server", "route_id", "session_version",
		"hostname", "public_url", "target", "started_at", "updated_at", "heartbeat_at", "lease_expires_at")
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
	if strings.TrimSpace(output.String()) != "No local tunnels." {
		t.Fatalf("status output = %q", output.String())
	}
}
