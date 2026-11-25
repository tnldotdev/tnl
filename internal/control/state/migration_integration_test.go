package state

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationWorkloadRenewalMigration(t *testing.T) {
	d, url, now := newControlStateIntegrationDatabaseWithURL(t, "workload_renewal_migration")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	r = selectedProjectRequest(r, "production")
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	exchange, key := workloadExchange(t, r, now)
	session, err := d.ExchangeWorkload(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	row := func() string {
		t.Helper()
		var value string
		if err := d.pool.QueryRow(ctx, `SELECT to_jsonb(w)::text FROM control.workload_sessions w WHERE id=$1`, session.ID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := row()
	if err := Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	if err := d.Readiness(ctx); err != nil {
		t.Fatal(err)
	}
	if row() != before {
		t.Fatal("migration changed existing session authority")
	}
	recovered, err := d.ExchangeWorkload(ctx, exchange, now)
	if err != nil || recovered.RenewalSequence != 0 || recovered.ID != session.ID || recovered.Credential != session.Credential || !recovered.LeaseExpiresAt.Equal(session.LeaseExpiresAt) {
		t.Fatal("migration lost committed session or initial counter", err)
	}
	if next, err := d.RenewWorkloadSession(ctx, session.ID, session.Credential, signWorkloadRenewal(recovered, key), now.Add(31*time.Second)); err != nil || next.RenewalSequence != 1 {
		t.Fatal("saved session could not renew with its original key", err)
	}
	if err := Migrate(ctx, url); err != nil {
		t.Fatal("repeat migration failed", err)
	}
}

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
	database, err := Open(ctx, databaseURL, testStorageKey, "", naming.ManagedURLModeGenerated)
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
	checkPrepared := func(db *Database, want bool) {
		t.Helper()
		conn, err := db.pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Release()
		const query = `SELECT $1::int + 1`
		var value int
		if err := conn.QueryRow(ctx, query, 41).Scan(&value); err != nil || value != 42 {
			t.Fatalf("pooled query returned %d: %v", value, err)
		}
		var prepared bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_prepared_statements WHERE statement=$1)`, query).Scan(&prepared); err != nil || prepared != want {
			t.Fatalf("query prepared on the PostgreSQL session = %t, want %t: %v", prepared, want, err)
		}
	}
	checkPrepared(database, true)
	ordinary, err := (PoolConfig{URL: databaseURL, DisablePreparedStatements: true}).Open(ctx, testStorageKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ordinary.Close)
	checkPrepared(ordinary, false)
	for _, table := range []string{
		"identities", "oidc_assertion_exchanges", "managed_label_reservations", "teams", "member_slug_reservations", "team_memberships", "team_invitations", "domains", "control_sessions", "guest_trials", "dns_authorities", "dns_challenge_changes",
		"services", "service_runs", "service_connection_slots", "relay_services", "relay_leases", "ingress_leases",
		"acme_accounts", "relay_certificate_orders", "acme_orders", "acme_authorizations", "ingress_run_fences",
		"service_recovery_episodes", "service_recovery_histogram", "admin_audit_events", "maintenance_controls", "schema_migration_lock",
	} {
		var exists bool
		if err := database.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'control' AND table_name = $1)`, table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Errorf("control.%s missing after migration", table)
		}
		var key string
		wantKey := "id"
		if table == "service_connection_slots" {
			wantKey = "publisher_connection_id"
		}
		if err := database.pool.QueryRow(ctx, `SELECT a.attname FROM pg_constraint AS c
			JOIN pg_attribute AS a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
			WHERE c.conrelid = ('control.' || $1)::regclass
			AND (c.contype='p' OR $1='service_connection_slots' AND c.contype='u' AND a.attname='publisher_connection_id')`, table).Scan(&key); err != nil || key != wantKey {
			t.Errorf("control.%s identity key = %q, %v; want %s", table, key, err, wantKey)
		}
	}
	for _, view := range []string{"publish_run_connection_slots", "publisher_service_connection_slots", "publisher_service_runs"} {
		var exists bool
		if err := database.pool.QueryRow(ctx, `SELECT to_regclass('control.'||$1) IS NOT NULL`, view).Scan(&exists); err != nil || exists {
			t.Errorf("control.%s retired view remains: %v", view, err)
		}
	}
	var version int64
	if err := database.pool.QueryRow(ctx, `SELECT MAX(version_id) FILTER (WHERE is_applied) FROM control.goose_db_version`).Scan(&version); err != nil || version != minimumSchemaVersion {
		t.Fatalf("schema version = %d, %v", version, err)
	}
	if _, err := database.pool.Exec(ctx, `INSERT INTO control.goose_db_version (version_id, is_applied) VALUES ($1, false)`, minimumSchemaVersion+1); err != nil {
		t.Fatal(err)
	}
	if err := database.Readiness(ctx); err != nil {
		t.Fatal("an unapplied migration does not change the serving schema", err)
	}
	if err := Migrate(ctx, databaseURL); err == nil || !strings.Contains(err.Error(), "expected applied schema version") {
		t.Fatal("migration treated an unapplied version as a newer schema", err)
	}
	// rejection must not bootstrap a lock or migration history in an older,
	// populated control schema, even when it predates those objects.
	if _, err := database.pool.Exec(ctx, `DROP TABLE control.schema_migration_lock,control.goose_db_version`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, databaseURL); err == nil {
		t.Fatal("migration accepted an unversioned populated schema")
	}
	var unchanged bool
	if err := database.pool.QueryRow(ctx, `SELECT to_regclass('control.schema_migration_lock') IS NULL
		AND to_regclass('control.goose_db_version') IS NULL AND to_regclass('control.services') IS NOT NULL`).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("migration changed an incompatible unversioned schema", err)
	}
}

func TestIntegrationScopedForeignKeys(t *testing.T) {
	f := newServicePublicationFixture(t)
	database, now, actor := f.database, f.now, f.actor(t)
	other, err := database.CreateTeam(t.Context(), authorityTeamRequest(actor), now)
	if err != nil {
		t.Fatal(err)
	}
	otherService, err := database.CreateServiceAt(t.Context(), other.ID, actor, "other", "other", ServicePlacement{}, now,
		ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.member_slug_reservations
		(id, team_id, member_slug, state, created_at) VALUES
		('reservation_owner_b_extra', $2, 'extra', 'invited', $1)`, now, other.ID); err != nil {
		t.Fatal(err)
	}
	work := createPlanIssuanceWork(t, database, now, f.run, f.prepared.CertificatePlan, false, nil)
	for _, test := range []struct {
		name, query string
		args        []any
	}{
		{name: "membership_slug", query: `UPDATE control.team_memberships SET slug_reservation_id = 'reservation_owner_b_extra' WHERE team_id = $1`, args: []any{f.service.TeamID}},
		{name: "invitation_slug", query: `INSERT INTO control.team_invitations (id, team_id, slug_reservation_id, initial_role,
			invited_by_identity_id, idempotency_key, request_digest, token_digest, state, created_at, expires_at)
			VALUES ('invitation_wrong_team', $1, 'reservation_owner_b_extra', 'member', $2,
			'wrong-team', decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), 'pending', now(), now() + interval '1 hour')`, args: []any{f.service.TeamID, actor}},
		{name: "service_run_team", query: `UPDATE control.service_runs SET service_id=$2 WHERE id=$1`, args: []any{f.run.RunID, otherService.ID}},
		{name: "missing_recovery_run", query: `INSERT INTO control.service_recovery_episodes (service_id, service_run_id, run_number, state, opened_at) VALUES ($1, 'srun_missing', 2, 'open', now())`, args: []any{f.service.ID}},
		{name: "acme_order_run", query: `UPDATE control.acme_orders SET service_id=$2 WHERE id=$1`, args: []any{work.ID, otherService.ID}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := database.pool.Exec(t.Context(), test.query, test.args...)
			var constraint *pgconn.PgError
			if !errors.As(err, &constraint) || constraint.Code != "23503" {
				t.Fatalf("foreign key error = %v; want 23503", err)
			}
		})
	}
	domain, err := database.ClaimTeamDomain(t.Context(), ClaimDomainRequest{
		IdentityID: actor, TeamID: other.ID, IdempotencyKey: "foreign-domain", Domain: "foreign.example.test",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.teams SET default_domain_id=$2 WHERE id=$1`, f.service.TeamID, domain.ID); err == nil {
		t.Fatal("another team's custom domain became the default")
	}
}

func TestIntegrationPublisherConnectionSchemaConstraints(t *testing.T) {
	f := newServicePublicationFixture(t)
	// exercise the constraints on real rows, rather than matching SQL source
	// spelling. each failing statement is atomic and leaves the fixture intact.
	for _, test := range []struct{ name, query, code string }{
		{"slot_lower_bound", `UPDATE control.service_connection_slots SET connection_slot = -1 WHERE connection_slot = 0`, "23514"},
		{"slot_upper_bound", `UPDATE control.service_connection_slots SET connection_slot = 2 WHERE connection_slot = 1`, "23514"},
		{"distinct_services", `UPDATE control.service_connection_slots SET relay_service_id = (SELECT relay_service_id FROM control.service_connection_slots WHERE connection_slot = 0) WHERE connection_slot = 1`, "23505"},
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
