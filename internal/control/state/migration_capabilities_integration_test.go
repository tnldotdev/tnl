package state

import (
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationMigrationRejectsCompatibilityViewBaseline(t *testing.T) {
	d, url, now := newControlStateIntegrationDatabaseWithURL(t, "compatibility_view_baseline")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	r = selectedProjectRequest(r, "production")
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	exchange, _ := workloadExchange(t, r, now)
	session, err := d.ExchangeWorkload(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	// retain the predecessor identity literally so later baseline edits cannot
	// silently turn this into a test of the current baseline.
	const previous = "tnl-control-fresh-v1-workload-gitlab"
	for _, query := range []string{
		`CREATE VIEW control.publish_run_publisher_grants AS
		 SELECT id AS publish_run_id, COALESCE(publisher_identity_id,'')::text AS publisher_identity_id,
		 COALESCE(publisher_grant_id,'')::text AS publisher_grant_id
		 FROM control.publish_runs WHERE publisher_identity_id IS NOT NULL`,
		`ALTER TABLE control.schema_identity DROP CONSTRAINT schema_identity_baseline_id_check`,
		`UPDATE control.schema_identity SET baseline_id='tnl-control-fresh-v1-workload-gitlab' WHERE id=1`,
		`ALTER TABLE control.schema_identity ADD CONSTRAINT schema_identity_baseline_id_check
		 CHECK (baseline_id='tnl-control-fresh-v1-workload-gitlab')`,
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
		var present bool
		if err := d.pool.QueryRow(ctx, `SELECT baseline_id,
		 to_regclass('control.publish_run_publisher_grants') IS NOT NULL
		 FROM control.schema_identity WHERE id=1`).Scan(&stored, &present); err != nil || stored != previous || !present {
			t.Fatalf("predecessor baseline = %q, view present = %t, %v", stored, present, err)
		}
	}
	assertPredecessor()
	snapshot := func() string {
		t.Helper()
		var value string
		if err := d.pool.QueryRow(ctx, `SELECT jsonb_build_array(
		 (SELECT jsonb_agg(v ORDER BY id) FROM control.goose_db_version v),
		 (SELECT to_jsonb(i) FROM control.schema_identity i WHERE id=1),
		 (SELECT pg_get_constraintdef(oid) FROM pg_constraint
		  WHERE conrelid='control.schema_identity'::regclass AND conname='schema_identity_baseline_id_check'),
		 pg_get_viewdef('control.publish_run_publisher_grants'::regclass),
		 (SELECT to_jsonb(w) FROM control.workload_sessions w WHERE id=$1))::text`, session.ID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
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
			if err == nil || !strings.Contains(err.Error(), "incompatible database baseline") || !strings.Contains(err.Error(), "use a fresh PostgreSQL database") {
				t.Fatalf("rejection = %v; want incompatible baseline with fresh-database diagnostic", err)
			}
			assertPredecessor()
			if snapshot() != before {
				t.Fatal("compatibility check changed predecessor migration records, identity, constraint, view, or workload session")
			}
		})
	}
}
