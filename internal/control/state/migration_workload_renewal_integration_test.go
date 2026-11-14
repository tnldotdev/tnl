package state

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationMigrationRejectsPreRenewalWorkloadBaseline(t *testing.T) {
	d, url, _ := newControlStateIntegrationDatabaseWithURL(t, "pre_renewal_baseline")
	ctx := t.Context()
	// reconstruct the predecessor's schema and identity. keep its identity
	// literal: using baselineID would hide the next incompatible baseline edit.
	const previous = "tnl-control-fresh-v1-connector-rebinding"
	for _, query := range []string{
		`DELETE FROM control.goose_db_version WHERE version_id > 1`,
		`ALTER TABLE control.workload_sessions DROP COLUMN renewal_sequence`,
		`ALTER TABLE control.schema_identity DROP CONSTRAINT schema_identity_baseline_id_check`,
		`UPDATE control.schema_identity SET baseline_id='tnl-control-fresh-v1-connector-rebinding' WHERE id=1`,
		`ALTER TABLE control.schema_identity ADD CONSTRAINT schema_identity_baseline_id_check
			CHECK (baseline_id='tnl-control-fresh-v1-connector-rebinding')`,
	} {
		if _, err := d.pool.Exec(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	assertPredecessor := func() {
		t.Helper()
		if version, err := readSchemaVersion(ctx, d.pool); err != nil || version != 1 {
			t.Fatalf("predecessor schema version = %d, %v; want 1", version, err)
		}
		var stored string
		if err := d.pool.QueryRow(ctx, `SELECT baseline_id FROM control.schema_identity WHERE id=1`).Scan(&stored); err != nil || stored != previous {
			t.Fatalf("predecessor baseline = %q, %v; want %q", stored, err, previous)
		}
		_, err := controlstatedb.New(d.pool).GetWorkloadSession(ctx, "missing-session")
		var postgresError *pgconn.PgError
		if !errors.As(err, &postgresError) || postgresError.Code != "42703" || !strings.Contains(postgresError.Message, "renewal_sequence") {
			t.Fatalf("predecessor workload query = %v; want undefined renewal_sequence (42703)", err)
		}
	}
	assertPredecessor()
	for _, check := range []struct {
		name string
		run  func() error
	}{
		{"migrate", func() error { return Migrate(ctx, url) }},
		{"readiness", func() error { return d.Readiness(ctx) }},
		{"open", func() error {
			opened, err := Open(ctx, url, testStorageKey, "", naming.ManagedURLModeGenerated)
			if opened != nil {
				opened.Close()
			}
			return err
		}},
	} {
		t.Run(check.name, func(t *testing.T) {
			err := check.run()
			if err == nil {
				t.Fatalf("accepted schema 1 baseline %q without workload_sessions.renewal_sequence", previous)
			}
			if !strings.Contains(err.Error(), "incompatible database baseline") || !strings.Contains(err.Error(), "use a fresh PostgreSQL database") {
				t.Fatalf("rejection = %v; want incompatible baseline with fresh-database diagnostic", err)
			}
		})
	}
	// rejection must not upgrade, backfill, or relabel the predecessor.
	assertPredecessor()
}
