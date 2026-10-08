package clientstate

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
)

func TestFinishedTunnelPersistsReasonInsteadOfCause(t *testing.T) {
	database, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	tunnel, err := database.BeginTunnel(t.Context(), BeginTunnelOptions{
		Command: TunnelCommandPublish, Server: "https://server.example", Target: "3000", Project: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("authorization token=secret-do-not-store")
	if err := tunnel.Finish(t.Context(), failure.Wrap("request control API", failure.ServerUnavailable, cause)); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := database.db.QueryRowContext(t.Context(), "SELECT last_error FROM local_tunnels WHERE id = ?", tunnel.ID()).Scan(&stored); err != nil || stored != string(failure.ServerUnavailable) {
		t.Fatalf("stored tunnel error = %q, %v", stored, err)
	}
}

func TestIntegrationGroupRegistrationHasTypedFailures(t *testing.T) {
	database, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	options := BeginTunnelOptions{Command: TunnelCommandPublish, Server: "https://server.example", Target: "3000", Project: t.TempDir(), IntegrationGroup: strings.Repeat("x", 1025)}
	if _, err := database.BeginTunnel(t.Context(), options); err == nil {
		t.Fatal("accepted an oversized integration group")
	} else if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ProjectConfigInvalid {
		t.Fatalf("integration group failure = %v", err)
	}
	options.IntegrationGroup = "project\x00member.example"
	tunnel, err := database.BeginTunnel(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.Finish(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetIntegrationGroup(t.Context(), options.IntegrationGroup); err == nil {
		t.Fatal("stopped tunnel registered an integration group")
	} else if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ClientStateUnavailable {
		t.Fatalf("stopped integration group registration failure = %v", err)
	}
}

func TestTunnelSnapshotTracksLifecycleConsistently(t *testing.T) {
	database, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	database.now = func() time.Time { return now }
	project := t.TempDir()
	tunnel, err := database.BeginTunnel(t.Context(), BeginTunnelOptions{
		Command: TunnelCommandPublish, Server: "https://server.example", Target: "3000",
		Project: project, Service: "web",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)

	assertTunnelSnapshot(t, database, TunnelStateStarting, TunnelSummary{Total: 1, Starting: 1})
	if err := tunnel.SetPublicURL(t.Context(), testPublicURLID, "route.example"); err != nil {
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
	if got.ID != tunnel.ID() || got.PublicURLID != testPublicURLID || got.PublishRunNumber != 3 ||
		got.PublicURL != "https://route.example" || got.Target != "http://127.0.0.1:3000" ||
		got.Project != project || got.Service != "web" {
		t.Fatalf("tunnel = %#v", got)
	}
	projectSnapshot, err := database.SnapshotProject(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(projectSnapshot.Tunnels) != 0 || projectSnapshot.Summary.Total != 0 {
		t.Fatalf("other project snapshot = %#v", projectSnapshot)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"publish_run_number":3`) || strings.Contains(string(encoded), `"session_version"`) {
		t.Fatalf("snapshot JSON publish run number fields = %s", encoded)
	}

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

func TestPersistedTunnelSnapshotExpiresWithoutHeartbeat(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	owner, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	now := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	owner.now = func() time.Time { return now }
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tunnel, err := owner.BeginTunnel(ctx, BeginTunnelOptions{
		Command: TunnelCommandPublish, Server: "https://server.example", Target: "3000", Project: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// simulate an owner exiting without Finish: retain the persisted row, but
	// stop and join lease maintenance before advancing the reader's clock.
	cancel()
	select {
	case <-tunnel.done:
	case <-time.After(time.Second):
		t.Fatal("heartbeat did not stop")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	for _, test := range []struct {
		name    string
		offset  time.Duration
		state   TunnelState
		summary TunnelSummary
	}{
		{"before", tunnelLeaseDuration - time.Nanosecond, TunnelStateStarting, TunnelSummary{Total: 1, Starting: 1}},
		{"at", tunnelLeaseDuration, TunnelStateStale, TunnelSummary{Total: 1, Stale: 1}},
		{"after", tunnelLeaseDuration + time.Nanosecond, TunnelStateStale, TunnelSummary{Total: 1, Stale: 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader.now = func() time.Time { return now.Add(test.offset) }
			snapshot := assertTunnelSnapshot(t, reader, test.state, test.summary)
			if snapshot.Tunnels[0].ID != tunnel.ID() || !snapshot.Tunnels[0].HeartbeatAt.Equal(now) {
				t.Fatalf("persisted snapshot changed: %#v", snapshot)
			}
		})
	}
}

func TestTunnelProjectStateIsPartOfInitialV1Migration(t *testing.T) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 || entries[0].Name() != "00001_schema.sql" {
		t.Fatalf("client-state migrations = %#v", entries)
	}
	data, err := migrationFiles.ReadFile("migrations/00001_schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"worktree_hash_salt BLOB NOT NULL", "length(worktree_hash_salt) IN (0, 32)",
		"project_root TEXT NOT NULL", "service TEXT NOT NULL", "local_tunnels_project_open_idx",
		"CREATE TABLE client_setting", "telemetry_enabled INTEGER NOT NULL",
	} {
		if !strings.Contains(string(data), required) {
			t.Fatalf("initial migration does not contain %q", required)
		}
	}
	if tunnelSnapshotSchemaVersion != 2 {
		t.Fatalf("tunnel snapshot schema version = %d", tunnelSnapshotSchemaVersion)
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
		Command: TunnelCommandDev, Server: "https://server.example", Project: t.TempDir(),
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

func TestLiveTunnelHeartbeatRenewsPersistedLease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		database, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		tunnel, err := database.BeginTunnel(t.Context(), BeginTunnelOptions{Command: TunnelCommandDev, Server: "https://server.example", Project: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		defer tunnel.Finish(context.Background(), nil)
		initial := assertTunnelSnapshot(t, database, TunnelStateStarting, TunnelSummary{Total: 1, Starting: 1}).Tunnels[0]
		synctest.Wait() // ensure the heartbeat ticker is running before advancing time.
		time.Sleep(tunnelLeaseDuration + tunnelHeartbeatInterval)
		synctest.Wait()
		renewed := assertTunnelSnapshot(t, database, TunnelStateStarting, TunnelSummary{Total: 1, Starting: 1}).Tunnels[0]
		if !renewed.HeartbeatAt.After(initial.LeaseExpiresAt) || !renewed.LeaseExpiresAt.Equal(renewed.HeartbeatAt.Add(tunnelLeaseDuration)) {
			t.Fatalf("lease was not renewed: initial=%#v renewed=%#v", initial, renewed)
		}
	})
}

func TestTunnelCancelsContextWhenLeaseCannotBeMaintained(t *testing.T) {
	database, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	database.heartbeatInterval = time.Millisecond
	tunnel, err := database.BeginTunnel(t.Context(), BeginTunnelOptions{
		Command: TunnelCommandPublish, Server: "https://server.example", Target: "3000", Project: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		tunnel.cancel(nil)
		select {
		case <-tunnel.done:
		case <-time.After(time.Second):
			t.Error("heartbeat did not join")
		}
	})
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
