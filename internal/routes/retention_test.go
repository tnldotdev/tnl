package routes

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/state"
)

func TestRunStateRetentionReportsErrorsAndStops(t *testing.T) {
	db, err := state.Open(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	reported := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunStateRetention(ctx, db, func(err error) { reported <- err })
	}()
	select {
	case err := <-reported:
		if !strings.Contains(err.Error(), "routes: begin state retention") {
			t.Fatalf("reported error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("state retention error was not reported")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("state retention did not stop after cancellation")
	}
}

func TestPruneRouteStatePreservesCurrentAndProtectedState(t *testing.T) {
	db, err := state.Open(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	old := now.Add(-2 * routeStateRetention).UnixNano()
	future := now.Add(time.Hour).UnixNano()
	for _, statement := range []string{
		"INSERT INTO identities (id, display_name, email, created_at) VALUES ('identity_test', 'Test', 'test@example.com', 1)",
		"INSERT INTO hostnames (id, identity_id, hostname, kind, status, source, created_at, activated_at) VALUES ('hostname_current', 'identity_test', 'current.routes.test', 'managed', 'active', 'user', 1, 1)",
		"INSERT INTO hostnames (id, identity_id, hostname, kind, status, source, created_at, activated_at) VALUES ('hostname_deleted', 'identity_test', 'deleted.routes.test', 'managed', 'active', 'user', 1, 1)",
		"INSERT INTO hostnames (id, identity_id, hostname, kind, status, source, created_at, activated_at) VALUES ('hostname_pending', 'identity_test', 'pending.routes.test', 'managed', 'active', 'user', 1, 1)",
		"INSERT INTO routes (id, hostname_id, identity_id, hostname, local_target, status, route_version, created_at) VALUES ('route_current', 'hostname_current', 'identity_test', 'current.routes.test', 'localhost:3000', 'enabled', 2, 1)",
	} {
		if _, err := db.ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	for _, route := range []struct{ id, hostnameID, hostname string }{
		{id: "route_deleted", hostnameID: "hostname_deleted", hostname: "deleted.routes.test"},
		{id: "route_pending", hostnameID: "hostname_pending", hostname: "pending.routes.test"},
	} {
		if _, err := db.ExecContext(t.Context(), `
			INSERT INTO routes (id, hostname_id, identity_id, hostname, local_target, status, route_version, created_at, deleted_at)
			VALUES (?, ?, 'identity_test', ?, 'localhost:3000', 'deleted', 1, 1, ?)
		`, route.id, route.hostnameID, route.hostname, old); err != nil {
			t.Fatal(err)
		}
	}
	for _, session := range []struct {
		id, routeID string
		version     int
	}{
		{id: "session_old", routeID: "route_current", version: 1},
		{id: "session_current", routeID: "route_current", version: 2},
		{id: "session_deleted", routeID: "route_deleted", version: 1},
	} {
		if _, err := db.ExecContext(t.Context(), `
			INSERT INTO route_sessions (
				id, route_id, route_version, status, token_id, secret_hash, server_instance_id,
				created_at, last_heartbeat_at, expires_at
			) VALUES (?, ?, ?, 'expired', ?, ?, 'instance', 1, 1, 2)
		`, session.id, session.routeID, session.version, session.id+"_token", []byte(session.id)); err != nil {
			t.Fatal(err)
		}
	}
	for _, version := range []int{1, 2} {
		if _, err := db.ExecContext(t.Context(), `
			INSERT INTO route_allowed_ip_prefixes (route_id, route_version, position, prefix)
			VALUES ('route_current', ?, 0, '192.0.2.0/24')
		`, version); err != nil {
			t.Fatal(err)
		}
	}
	for _, use := range []struct {
		id      string
		expires int64
	}{
		{id: "expired", expires: old},
		{id: "live", expires: future},
	} {
		if _, err := db.ExecContext(t.Context(), `
			INSERT INTO route_authorization_uses (
				authorization_issuer, authorization_id, authorization_key_id, authorization_retry_id,
				authorization_revision, authorization_expires_at, operation, route_id, route_version,
				hostname, request_hash, created_at
			) VALUES ('issuer', ?, ?, ?, 1, ?, 'route_session.create', 'route_current', 1,
				'current.routes.test', zeroblob(32), 1)
		`, use.id, use.id+"_key", use.id+"_retry", use.expires); err != nil {
			t.Fatal(err)
		}
	}
	certificateSQL := `
		INSERT INTO certificate_issuances (
			id, route_id, route_version, hostname, directory_url, acme_profile, status, csr_der, csr_hash, spki_hash,
			order_started_at, order_expires_at, certificate_pem, not_after, created_at, updated_at
		) VALUES (?, 'route_current', 1, 'current.routes.test', 'https://acme.test/directory', 'tlsserver', ?, X'01', ?, X'02', ?, ?, ?, ?, ?, ?)
	`
	for _, issuance := range []struct {
		id, status             string
		orderStarted           any
		orderExpires, notAfter any
		certificate            any
		createdAt, updatedAt   int64
	}{
		{id: "certificate_failed", status: "failed", orderStarted: old, createdAt: old, updatedAt: old},
		{id: "certificate_stale_ambiguous", status: "creating_order", createdAt: old, updatedAt: old},
		{id: "certificate_ambiguous", status: "creating_order", orderStarted: now.UnixNano(), createdAt: old, updatedAt: now.UnixNano()},
		{id: "certificate_reusable", status: "installed", certificate: []byte("certificate"), notAfter: future, createdAt: old, updatedAt: old},
	} {
		if _, err := db.ExecContext(t.Context(), certificateSQL,
			issuance.id, issuance.status, []byte(issuance.id), issuance.orderStarted, issuance.orderExpires,
			issuance.certificate, issuance.notAfter, issuance.createdAt, issuance.updatedAt,
		); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(t.Context(), `
		INSERT INTO route_lifecycle_events (event_id, route_id, route_version, sequence, occurred_at, transition)
		VALUES ('event_pending', 'route_pending', 1, 1, ?, 'deleted')
	`, old); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `
		INSERT INTO route_usage_outbox_items (source_kind, source_id, source_revision, enqueued_at)
		SELECT 'lifecycle_event', id, 1, 1 FROM route_lifecycle_events WHERE route_id = 'route_pending'
	`); err != nil {
		t.Fatal(err)
	}

	store, err := NewStore(db, "routes.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.pruneRouteState(t.Context(), now); err != nil {
		t.Fatal(err)
	}

	assertRetentionCount(t, db, "SELECT COUNT(*) FROM route_sessions WHERE id = 'session_old'", 0)
	assertRetentionCount(t, db, "SELECT COUNT(*) FROM route_sessions WHERE id = 'session_current'", 1)
	assertRetentionCount(t, db, "SELECT COUNT(*) FROM route_allowed_ip_prefixes WHERE route_id = 'route_current' AND route_version = 1", 0)
	assertRetentionCount(t, db, "SELECT COUNT(*) FROM route_allowed_ip_prefixes WHERE route_id = 'route_current' AND route_version = 2", 1)
	assertRetentionCount(t, db, "SELECT COUNT(*) FROM route_authorization_uses WHERE authorization_id = 'expired'", 0)
	assertRetentionCount(t, db, "SELECT COUNT(*) FROM route_authorization_uses WHERE authorization_id = 'live'", 1)
	assertRetentionCount(t, db, "SELECT COUNT(*) FROM certificate_issuances WHERE id = 'certificate_failed'", 0)
	assertRetentionCount(t, db, "SELECT COUNT(*) FROM certificate_issuances WHERE id = 'certificate_stale_ambiguous'", 0)
	assertRetentionCount(t, db, "SELECT COUNT(*) FROM certificate_issuances WHERE id IN ('certificate_ambiguous', 'certificate_reusable')", 2)
	assertRetentionCount(t, db, "SELECT COUNT(*) FROM routes WHERE id = 'route_deleted'", 0)
	assertRetentionCount(t, db, "SELECT COUNT(*) FROM hostnames WHERE id = 'hostname_deleted'", 1)
	assertRetentionCount(t, db, "SELECT COUNT(*) FROM routes WHERE id = 'route_pending'", 1)
}

func assertRetentionCount(t *testing.T, db *sql.DB, query string, want int) {
	t.Helper()
	var got int
	if err := db.QueryRowContext(t.Context(), query).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("count for %q = %d, want %d", query, got, want)
	}
}
