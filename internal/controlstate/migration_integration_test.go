package controlstate

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func TestIntegrationControlSchemaUpgradeFromV1(t *testing.T) {
	for _, initialVersion := range []int{1, 2, 3, 4} {
		t.Run(fmt.Sprintf("v%d", initialVersion), func(t *testing.T) {
			testControlSchemaUpgrade(t, initialVersion)
		})
	}
}

func testControlSchemaUpgrade(t *testing.T, initialVersion int) {
	t.Helper()
	url := newDisposableControlStateDatabaseURL(t, fmt.Sprintf("schema_upgrade_v%d", initialVersion))
	config, err := parseDirectConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	db := stdlib.OpenDB(*config)
	t.Cleanup(func() { _ = db.Close() })
	if err := createMigrationLock(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	baseline, err := migrationFiles.ReadFile("migrations/00001_baseline.sql")
	if err != nil {
		t.Fatal(err)
	}
	previous := fstest.MapFS{"00001_baseline.sql": &fstest.MapFile{Data: baseline}}
	if initialVersion >= 2 {
		recovery, err := migrationFiles.ReadFile("migrations/00002_recovery.sql")
		if err != nil {
			t.Fatal(err)
		}
		previous["00002_recovery.sql"] = &fstest.MapFile{Data: recovery}
	}
	if initialVersion >= 3 {
		changes, err := migrationFiles.ReadFile("migrations/00003_dns_challenge_changes.sql")
		if err != nil {
			t.Fatal(err)
		}
		previous["00003_dns_challenge_changes.sql"] = &fstest.MapFile{Data: changes}
	}
	if initialVersion >= 4 {
		cleanup, err := migrationFiles.ReadFile("migrations/00004_acme_cleanup_work.sql")
		if err != nil {
			t.Fatal(err)
		}
		previous["00004_acme_cleanup_work.sql"] = &fstest.MapFile{Data: cleanup}
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, previous,
		goose.WithTableName(versionTable), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Up(t.Context()); err != nil {
		t.Fatal(err)
	}
	if initialVersion >= 3 {
		// later migrations leave existing runtime queries usable across the upgrade.
		active, err := Open(t.Context(), url, testStorageKey, "")
		if err != nil {
			t.Fatal(err)
		}
		defer active.Close()
		if err := active.Readiness(t.Context()); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := active.Readiness(t.Context()); err != nil {
				t.Errorf("pre-migration runtime after upgrade: %v", err)
			}
		}()
	} else if premature, err := Open(t.Context(), url, testStorageKey, ""); err == nil {
		premature.Close()
		t.Fatalf("Open accepted incompatible v%d schema", initialVersion)
	}
	if err := Migrate(t.Context(), url); err != nil {
		t.Fatalf("upgrade existing control schema: %v", err)
	}
	upgraded, err := Open(t.Context(), url, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	if err := upgraded.Readiness(t.Context()); err != nil {
		t.Fatal(err)
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
		"public_urls", "publish_runs", "publish_run_connections", "relay_services", "relay_leases", "ingress_leases", "ingress_routing_table_clock", "ingress_routing_table_events",
		"control_tls_cache", "acme_accounts", "relay_certificate_orders", "acme_orders", "acme_authorizations", "ingress_usage_runs", "ingress_usage_reports",
		"public_url_usage_buckets", "public_url_usage_deliveries", "public_url_recovery_episodes", "public_url_recovery_histogram", "admin_audit_events", "maintenance_controls",
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
	// A newer additive migration must not make serving processes unready.
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

func TestIntegrationPublisherConnectionSchemaConstraints(t *testing.T) {
	f := newPublishRunFixture(t)
	// Exercise the constraints on real rows, rather than matching SQL source
	// spelling. Each failing statement is atomic and leaves the fixture intact.
	for _, test := range []struct{ name, query, code string }{
		{"slot_lower_bound", `UPDATE control.publish_run_connections SET connection_slot = -1 WHERE connection_slot = 0`, "23514"},
		{"slot_upper_bound", `UPDATE control.publish_run_connections SET connection_slot = 2 WHERE connection_slot = 1`, "23514"},
		{"distinct_services", `UPDATE control.publish_run_connections SET relay_service_id = (SELECT relay_service_id FROM control.publish_run_connections WHERE connection_slot = 0) WHERE connection_slot = 1`, "23505"},
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
