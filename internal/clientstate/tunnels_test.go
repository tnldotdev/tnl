package clientstate

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTunnelSnapshotTracksLifecycleConsistently(t *testing.T) {
	database, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	database.now = func() time.Time { return now }
	tunnel, err := database.BeginTunnel(t.Context(), BeginTunnelOptions{
		Command: TunnelCommandPublish, Server: "https://server.example", Target: "3000",
	})
	if err != nil {
		t.Fatal(err)
	}

	assertTunnelSnapshot(t, database, TunnelStateStarting, TunnelSummary{Total: 1, Starting: 1})
	if err := tunnel.SetRoute(t.Context(), testRouteID, "route.example"); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetProvisioning(t.Context(), 3); err != nil {
		t.Fatal(err)
	}
	assertTunnelSnapshot(t, database, TunnelStateProvisioning, TunnelSummary{Total: 1, Provisioning: 1})
	if err := tunnel.SetReady(t.Context(), "https://route.example", 3); err != nil {
		t.Fatal(err)
	}
	snapshot := assertTunnelSnapshot(t, database, TunnelStateReady, TunnelSummary{Total: 1, Ready: 1})
	got := snapshot.Tunnels[0]
	if got.ID != tunnel.ID() || got.RouteID != testRouteID || got.RouteVersion != 3 ||
		got.PublicURL != "https://route.example" || got.Target != "http://127.0.0.1:3000" {
		t.Fatalf("tunnel = %#v", got)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"route_version":3`) || strings.Contains(string(encoded), `"session_version"`) {
		t.Fatalf("snapshot JSON route version fields = %s", encoded)
	}

	now = now.Add(tunnelLeaseDuration + time.Nanosecond)
	assertTunnelSnapshot(t, database, TunnelStateStale, TunnelSummary{Total: 1, Stale: 1})
	if err := tunnel.Finish(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	snapshot, err = database.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Summary.Total != 0 || len(snapshot.Tunnels) != 0 {
		t.Fatalf("finished snapshot = %#v", snapshot)
	}
}

func TestTunnelSnapshotIsSharedAcrossProcesses(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	owner, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	tunnel, err := owner.BeginTunnel(t.Context(), BeginTunnelOptions{
		Command: TunnelCommandDev, Server: "https://server.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	if err := tunnel.SetDevTarget(t.Context(), "vite", "5173"); err != nil {
		t.Fatal(err)
	}

	reader, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	snapshot, err := reader.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Tunnels) != 1 || snapshot.Tunnels[0].ID != tunnel.ID() ||
		snapshot.Tunnels[0].Framework != "vite" || snapshot.Tunnels[0].Target != "http://127.0.0.1:5173" {
		t.Fatalf("shared snapshot = %#v", snapshot)
	}
}

func TestTunnelCancelsContextWhenLeaseCannotBeMaintained(t *testing.T) {
	database, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	database.heartbeatInterval = time.Millisecond
	tunnel, err := database.BeginTunnel(t.Context(), BeginTunnelOptions{
		Command: TunnelCommandPublish, Server: "https://server.example", Target: "3000",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-tunnel.Context().Done():
		if cause := context.Cause(tunnel.Context()); cause == nil ||
			!strings.Contains(cause.Error(), "maintain tunnel lease") {
			t.Fatalf("tunnel context cause = %v", cause)
		}
	case <-time.After(time.Second):
		t.Fatal("tunnel context was not canceled after the database closed")
	}
}

func assertTunnelSnapshot(
	t *testing.T, database *Database, wantState TunnelState, wantSummary TunnelSummary,
) TunnelSnapshot {
	t.Helper()
	snapshot, err := database.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Tunnels) != 1 || snapshot.Tunnels[0].State != wantState || snapshot.Summary != wantSummary {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	return snapshot
}
