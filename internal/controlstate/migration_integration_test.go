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
		"identities", "oidc_assertion_exchanges", "managed_label_reservations", "teams", "member_slug_reservations", "team_memberships", "team_invitations", "domains", "control_sessions",
		"routes", "route_sessions", "route_session_connections", "relay_services", "relay_leases", "ingress_leases", "ingress_routing_table_clock", "ingress_routing_table_events",
		"control_tls_cache", "acme_accounts", "relay_certificate_orders", "acme_orders", "acme_authorizations", "ingress_usage_runs", "ingress_usage_reports",
		"route_usage_buckets", "route_usage_deliveries", "route_recovery_episodes", "route_recovery_histogram", "admin_audit_events", "maintenance_controls",
	} {
		var exists bool
		if err := database.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'control' AND table_name = $1)`, table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Errorf("control.%s missing after migration", table)
		}
	}
	var version int64
	if err := database.pool.QueryRow(ctx, `SELECT MAX(version_id) FILTER (WHERE is_applied) FROM control.goose_db_version`).Scan(&version); err != nil || version != schemaVersion {
		t.Fatalf("schema version = %d, %v", version, err)
	}
	if _, err := database.pool.Exec(ctx, `INSERT INTO control.goose_db_version (version_id, is_applied) VALUES ($1, true)`, schemaVersion+1); err != nil {
		t.Fatal(err)
	}
	if err := database.Readiness(ctx); err == nil {
		t.Fatal("Readiness accepted incompatible schema")
	}
	if incompatible, err := Open(ctx, databaseURL, testStorageKey, ""); err == nil {
		incompatible.Close()
		t.Fatal("Open accepted incompatible schema")
	}
}

func TestIntegrationPublisherConnectionSchemaConstraints(t *testing.T) {
	f := newRouteSessionFixture(t)
	// Exercise the constraints on real rows, rather than matching SQL source
	// spelling. Each failing statement is atomic and leaves the fixture intact.
	for _, test := range []struct{ name, query, code string }{
		{"slot_lower_bound", `UPDATE control.route_session_connections SET connection_slot = -1 WHERE connection_slot = 0`, "23514"},
		{"slot_upper_bound", `UPDATE control.route_session_connections SET connection_slot = 2 WHERE connection_slot = 1`, "23514"},
		{"distinct_services", `UPDATE control.route_session_connections SET relay_service_id = (SELECT relay_service_id FROM control.route_session_connections WHERE connection_slot = 0) WHERE connection_slot = 1`, "23505"},
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
