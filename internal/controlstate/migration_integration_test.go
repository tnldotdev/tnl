package controlstate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestIntegrationPostgresMigrationAndOpen(t *testing.T) {
	databaseURL := newDisposableControlStateDatabaseURL(t, "migration")
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	const callers = 4
	results := make(chan error, callers)
	for range callers {
		workers.Go(func() { results <- Migrate(ctx, databaseURL) })
	}
	for range callers {
		if err := awaitIntegrationResult(t, ctx, results); err != nil {
			t.Fatalf("concurrent migration: %v", err)
		}
	}
	if err := Migrate(ctx, databaseURL); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}
	database, err := Open(ctx, databaseURL, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	if err := database.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if err := database.Readiness(ctx); err != nil {
		t.Fatal(err)
	}
	if mode := database.pool.Config().ConnConfig.DefaultQueryExecMode; mode != pgx.QueryExecModeExec {
		t.Fatalf("query mode = %v, want exec", mode)
	}
	for _, table := range []string{
		"identities", "oidc_assertion_exchanges", "managed_label_reservations", "teams", "member_slug_reservations", "team_memberships", "team_invitations", "domains", "control_sessions", "authority_revision_states", "runtime_secret", "dns_authorities", "dns_challenge_changes",
		"public_urls", "publish_runs", "publish_run_connection_slots", "relay_services", "relay_leases", "ingress_leases", "ingress_routing_table_clock", "ingress_routing_table_events", "relay_service_assignment_totals",
		"control_tls_cache", "acme_accounts", "relay_certificate_orders", "acme_orders", "acme_authorizations", "ingress_usage_runs", "ingress_usage_reports",
		"public_url_usage_configuration", "public_url_usage_buckets", "public_url_usage_deliveries", "public_url_recovery_episodes", "public_url_recovery_histogram", "admin_audit_events", "maintenance_controls", "schema_migration_lock",
	} {
		var exists bool
		if err := database.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'control' AND table_name = $1)`, table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Errorf("control.%s missing after migration", table)
		}
		var key string
		if err := database.pool.QueryRow(ctx, `SELECT a.attname FROM pg_constraint AS c
			JOIN pg_attribute AS a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
			WHERE c.conrelid = ('control.' || $1)::regclass AND c.contype = 'p'`, table).Scan(&key); err != nil || key != "id" {
			t.Errorf("control.%s primary key = %q, %v; want id", table, key, err)
		}
	}
	var version int64
	if err := database.pool.QueryRow(ctx, `SELECT MAX(version_id) FILTER (WHERE is_applied) FROM control.goose_db_version`).Scan(&version); err != nil || version != schemaVersion {
		t.Fatalf("schema version = %d, %v", version, err)
	}
	// a newer additive migration must not make serving processes unready.
	if _, err := database.pool.Exec(ctx, `ALTER TABLE control.public_urls ADD COLUMN future_note text`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(ctx, `INSERT INTO control.goose_db_version (version_id, is_applied) VALUES ($1, true)`, schemaVersion+1); err != nil {
		t.Fatal(err)
	}
	if err := database.Readiness(ctx); err != nil {
		t.Fatalf("Readiness rejected additive newer schema: %v", err)
	}
	newer, err := Open(ctx, databaseURL, testStorageKey, "")
	if err != nil {
		t.Fatalf("Open rejected additive newer schema: %v", err)
	}
	newer.Close()
}

func TestIntegrationScopedForeignKeys(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "scoped_foreign_keys")
	seedControlPublicURL(t, database, now, "owner_a")
	seedControlPublicURL(t, database, now, "owner_b")
	insertTestPublishRun(t, database, testPublishRun{
		ID: "session_owner_a", PublicURLID: "public_url_owner_a", TeamID: "team_owner_a",
		ActingIdentityID: "identity_owner_a", CertificateCacheKey: "owner_a", CertificateScope: "owner_a",
		CertificateIdentifiers: []string{"route-owner_a.example.test"}, ChallengeMethod: "tls-alpn-01",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.member_slug_reservations
		(id, team_id, member_slug, state, created_at) VALUES
		('reservation_owner_b_extra', 'team_owner_b', 'extra', 'invited', $1)`, now); err != nil {
		t.Fatal(err)
	}
	account, err := database.EnsureACMEAccount(t.Context(), "https://acme.example.test/scoped-fk", "operator@example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, query string
		args        []any
	}{
		{name: "membership_slug", query: `UPDATE control.team_memberships SET slug_reservation_id = 'reservation_owner_b_extra' WHERE team_id = 'team_owner_a'`},
		{name: "invitation_slug", query: `INSERT INTO control.team_invitations (id, team_id, slug_reservation_id, initial_role,
			invited_by_identity_id, idempotency_key, request_digest, token_digest, state, created_at, expires_at)
			VALUES ('invitation_wrong_team', 'team_owner_a', 'reservation_owner_b_extra', 'member', 'identity_owner_a',
			'wrong-team', decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), 'pending', now(), now() + interval '1 hour')`},
		{name: "publish_run_team", query: `UPDATE control.publish_runs SET team_id = 'team_owner_b' WHERE id = 'session_owner_a'`},
		{name: "missing_recovery_run", query: `INSERT INTO control.public_url_recovery_episodes (public_url_id, publish_run_number, state, opened_at) VALUES ('public_url_owner_a', 2, 'open', now())`},
		{name: "acme_order_run", query: `INSERT INTO control.acme_orders (id, account_id, publish_run_id, public_url_id, publish_run_number,
			idempotency_key, request_digest, certificate_cache_key, certificate_scope, certificate_identifiers,
			challenge_method, csr_der, csr_digest, state, available_at, created_at, updated_at)
			VALUES ('order_wrong_run', $1, 'session_owner_a', 'public_url_owner_b', 1,
			'wrong-run', decode(repeat('03', 32), 'hex'), 'owner_a', 'owner_a', ARRAY['owner-a.example.test'],
			'tls-alpn-01', decode('01', 'hex'), decode(repeat('04', 32), 'hex'), 'pending', now(), now(), now())`, args: []any{account.ID}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := database.pool.Exec(t.Context(), test.query, test.args...)
			var constraint *pgconn.PgError
			if !errors.As(err, &constraint) || constraint.Code != "23503" {
				t.Fatalf("foreign key error = %v; want 23503", err)
			}
		})
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.teams SET default_domain_id = 'domain_owner_b' WHERE id = 'team_owner_a'`); err == nil {
		t.Fatal("another team's claimed domain became the default")
	}
}

func TestIntegrationPublisherConnectionSchemaConstraints(t *testing.T) {
	f := newPublishRunFixture(t)
	// exercise the constraints on real rows, rather than matching SQL source
	// spelling. each failing statement is atomic and leaves the fixture intact.
	for _, test := range []struct{ name, query, code string }{
		{"slot_lower_bound", `UPDATE control.publish_run_connection_slots SET connection_slot = -1 WHERE connection_slot = 0`, "23514"},
		{"slot_upper_bound", `UPDATE control.publish_run_connection_slots SET connection_slot = 2 WHERE connection_slot = 1`, "23514"},
		{"distinct_services", `UPDATE control.publish_run_connection_slots SET relay_service_id = (SELECT relay_service_id FROM control.publish_run_connection_slots WHERE connection_slot = 0) WHERE connection_slot = 1`, "23505"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := f.database.pool.Exec(t.Context(), test.query)
			var postgresError *pgconn.PgError
			if !errors.As(err, &postgresError) || postgresError.Code != test.code {
				t.Fatalf("constraint error = %v, want SQLSTATE %s", err, test.code)
			}
		})
	}
}
