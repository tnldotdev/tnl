package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
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
	if err := database.db.QueryRowContext(t.Context(), "SELECT failure_code FROM local_tunnels WHERE id = ?", tunnel.ID()).Scan(&stored); err != nil || stored != string(failure.ServerUnavailable) {
		t.Fatalf("stored tunnel error = %q, %v", stored, err)
	}
}

func TestIntegrationScopeRegistrationHasTypedFailures(t *testing.T) {
	database, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	options := BeginTunnelOptions{Command: TunnelCommandPublish, Server: "https://server.example", Target: "3000", Project: t.TempDir(),
		IntegrationScope: IntegrationScope{PrimaryProjectRoot: "/" + strings.Repeat("x", 1024), Namespace: "member.example"}}
	if _, err := database.BeginTunnel(t.Context(), options); err == nil {
		t.Fatal("accepted an oversized integration group")
	} else if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ProjectConfigInvalid {
		t.Fatalf("integration group failure = %v", err)
	}
	options.IntegrationScope = IntegrationScope{PrimaryProjectRoot: options.Project, Namespace: "member.example"}
	tunnel, err := database.BeginTunnel(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.Finish(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetIntegrationScope(t.Context(), options.IntegrationScope); err == nil {
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

func TestTunnelRequiresPublicationAndTarget(t *testing.T) {
	database, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for _, options := range []BeginTunnelOptions{
		{Command: "dev", Server: "https://server.example", Target: "3000", Project: t.TempDir()},
		{Command: TunnelCommandPublish, Server: "https://server.example", Project: t.TempDir()},
	} {
		if _, err := database.BeginTunnel(t.Context(), options); err == nil {
			t.Fatal("accepted a tunnel without a publication and target")
		}
	}
	snapshot, err := database.Snapshot(t.Context())
	if err != nil || len(snapshot.Tunnels) != 0 {
		t.Fatalf("invalid publication left a tunnel: %#v, %v", snapshot, err)
	}
}

func TestServiceProtocolsShareLocalPublicationJournalWithoutPublicEndpoints(t *testing.T) {
	database, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for _, protocol := range []controlv1.ServiceProtocol{controlv1.ServiceProtocolHTTP, controlv1.Postgres, controlv1.Mysql, controlv1.Tcp, controlv1.Kubernetes} {
		t.Run(string(protocol), func(t *testing.T) {
			project := t.TempDir()
			target, canonical := "15432", "127.0.0.1:15432"
			if protocol == controlv1.ServiceProtocolHTTP {
				target, canonical = "3000", "http://127.0.0.1:3000"
			} else if protocol == controlv1.Kubernetes {
				target, canonical = "https://127.0.0.1:16443", "https://127.0.0.1:16443"
			}
			runtime, err := database.ReadRuntimeSnapshot(t.Context(), project)
			if err != nil {
				t.Fatal(err)
			}
			tunnel, err := database.BeginTunnel(t.Context(), BeginTunnelOptions{
				Command: TunnelCommandPublish, Server: "https://server.example", Target: target,
				Project: project, Service: "orders", ServiceProtocol: protocol,
			})
			if err != nil {
				t.Fatal("service publication could not join the local journal", protocol, err)
			}
			t.Cleanup(func() { _ = tunnel.Finish(context.Background(), nil) })
			assertTunnelSnapshot(t, database, TunnelStateStarting, TunnelSummary{Total: 1, Starting: 1})
			if err := tunnel.SetProvisioning(t.Context(), 7); err != nil {
				t.Fatal(err)
			}
			assertTunnelSnapshot(t, database, TunnelStateProvisioning, TunnelSummary{Total: 1, Provisioning: 1})
			if err := tunnel.SetReady(t.Context(), "", 7); err != nil {
				t.Fatal(err)
			}
			snapshot := assertTunnelSnapshot(t, database, TunnelStateReady, TunnelSummary{Total: 1, Ready: 1})
			saved := snapshot.Tunnels[0]
			if saved.ID != tunnel.ID() || saved.ServiceProtocol != protocol || saved.Target != canonical || saved.Project != project || saved.Service != "orders" ||
				saved.PublicURL != "" || saved.Hostname != "" || saved.PublicURLID != "" || saved.PublishRunNumber != 7 {
				t.Fatal("local publication invented a public endpoint or lost its protocol/run", saved)
			}
			if err := tunnel.Finish(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			events, err := database.RuntimeEventsAfter(t.Context(), project, runtime.Cursor)
			if err != nil {
				t.Fatal(err)
			}
			var states []TunnelState
			for _, event := range events {
				var payload struct {
					Publication TunnelInfo `json:"publication"`
				}
				if err := json.Unmarshal(event.Payload, &payload); err != nil {
					t.Fatal(err)
				}
				publication := payload.Publication
				if publication.ID != tunnel.ID() || publication.ServiceProtocol != protocol || publication.Target != canonical ||
					publication.PublicURL != "" || publication.Hostname != "" || publication.PublicURLID != "" {
					t.Fatal("journal event lost the protocol or invented an endpoint", publication)
				}
				states = append(states, publication.State)
			}
			if want := []TunnelState{TunnelStateStarting, TunnelStateProvisioning, TunnelStateReady, TunnelStateStopped}; !reflect.DeepEqual(states, want) {
				t.Fatalf("service publication journal states=%v, want %v", states, want)
			}
		})
	}
	for _, protocol := range []controlv1.ServiceProtocol{"redis", "ssh", "HTTP", "unknown"} {
		if _, err := database.BeginTunnel(t.Context(), BeginTunnelOptions{Command: TunnelCommandPublish,
			Server: "https://server.example", Target: "127.0.0.1:15432", Project: t.TempDir(), ServiceProtocol: protocol}); err == nil {
			t.Fatal("journal accepted an unsupported service protocol", protocol)
		}
	}
	snapshot, err := database.Snapshot(t.Context())
	if err != nil || len(snapshot.Tunnels) != 0 {
		t.Fatalf("invalid service left a public tunnel: %#v, %v", snapshot, err)
	}
}

func TestTunnelCancellationDoesNotHideIndependentFailure(t *testing.T) {
	database, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	failed := failure.Wrap("close service run", failure.ServerUnavailable, errors.New("private-operation-cause"))
	for _, tc := range []struct {
		name  string
		err   error
		state TunnelState
		code  string
	}{
		{"success", nil, TunnelStateStopped, ""},
		{"canceled", context.Canceled, TunnelStateStopped, ""},
		{"wrapped_canceled", fmt.Errorf("stop: %w", context.Canceled), TunnelStateStopped, ""},
		{"joined_canceled", errors.Join(context.Canceled, fmt.Errorf("join: %w", context.Canceled)), TunnelStateStopped, ""},
		{"failure", failed, TunnelStateFailed, string(failure.ServerUnavailable)},
		{"joined_failure", errors.Join(context.Canceled, failed), TunnelStateFailed, string(failure.ServerUnavailable)},
		{"wrapped_joined_failure", fmt.Errorf("stop: %w", errors.Join(context.Canceled, failed)), TunnelStateFailed, string(failure.ServerUnavailable)},
		{"untyped_cleanup_failure", errors.Join(context.Canceled, errors.New("private-cleanup-cause")), TunnelStateFailed, string(failure.Unexpected)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tunnel, err := database.BeginTunnel(t.Context(), BeginTunnelOptions{Command: TunnelCommandPublish,
				Server: "https://server.example", Target: "3000", Project: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = tunnel.Finish(context.Background(), nil) })
			if err := tunnel.Finish(t.Context(), tc.err); err != nil {
				t.Fatal(err)
			}
			if err := tunnel.Finish(t.Context(), nil); err != nil {
				t.Fatal("repeated finish failed", err)
			}
			select {
			case <-tunnel.done:
			default:
				t.Fatal("finish did not join lease maintenance")
			}
			if tunnel.Context().Err() == nil {
				t.Fatal("finish retained a live publication context")
			}
			if err := tunnel.SetReady(t.Context(), "", 9); err == nil {
				t.Fatal("finished publication accepted a late readiness mutation")
			}
			var state, code string
			if err := database.db.QueryRowContext(t.Context(), `SELECT state,COALESCE(failure_code,'') FROM local_tunnels WHERE id=?`, tunnel.ID()).Scan(&state, &code); err != nil || state != string(tc.state) || code != tc.code {
				t.Fatalf("terminal outcome=%q/%q, want %q/%q: %v", state, code, tc.state, tc.code, err)
			}
			snapshot, err := database.Snapshot(t.Context())
			if err != nil || len(snapshot.Tunnels) != 0 || snapshot.Summary.Total != 0 {
				t.Fatalf("finished publication retained an active journal row: %+v, %v", snapshot, err)
			}
		})
	}
}

func TestPublicTunnelAddressRejectsOpaquePorts(t *testing.T) {
	for _, address := range []string{"shell.example:10022", "tcp://db.example:5432", "https://db.example:5432", "https://db.example:"} {
		if _, err := parsePublicTunnelAddress(address); err == nil {
			t.Fatalf("public HTTP tunnel accepted %q", address)
		}
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

func TestTunnelProjectStateIsPartOfFreshV1Baseline(t *testing.T) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "00001_schema.sql" {
		t.Fatalf("client-state migrations = %#v", entries)
	}
	data, err := migrationFiles.ReadFile("migrations/00001_schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"worktree_hash_salt BLOB CHECK", "worktree_hash_salt IS NULL OR length(worktree_hash_salt) = 32",
		"project_root TEXT NOT NULL", "service TEXT NOT NULL", "local_tunnels_project_open_idx",
		"CREATE TABLE installation_settings", "telemetry_enabled INTEGER NOT NULL",
	} {
		if !strings.Contains(string(data), required) {
			t.Fatalf("initial migration does not contain %q", required)
		}
	}
	if tunnelSnapshotSchemaVersion != 1 {
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
		Command: TunnelCommandPublish, Server: "https://server.example", Project: t.TempDir(), Target: "5173",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
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
		snapshot.Tunnels[0].Command != TunnelCommandPublish || snapshot.Tunnels[0].Target != "http://127.0.0.1:5173" {
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
		tunnel, err := database.BeginTunnel(t.Context(), BeginTunnelOptions{Command: TunnelCommandPublish, Server: "https://server.example", Project: t.TempDir(), Target: "3000"})
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
