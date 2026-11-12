package state

import (
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationMigrationRejectsPreApprovalEnvironmentBaseline(t *testing.T) {
	d, url, now := newControlStateIntegrationDatabaseWithURL(t, "pre_approval_baseline")
	r := retainedEnvironmentProject(t, d, now)
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	environment, _ := createTestEnvironment(t, d, r, "preserved", definition.Revision, EnvironmentTargets{"api": {Address: "preserved.internal:3000"}})
	// the previous environment baseline has no atomic approval receipts. its
	// version-one identity must not admit serving or silently install new state.
	for _, query := range []string{
		`DROP TABLE control.workload_approvals`,
		`ALTER TABLE control.schema_identity DROP CONSTRAINT schema_identity_baseline_id_check`,
		`UPDATE control.schema_identity SET baseline_id='tnl-control-fresh-v1-explicit-capabilities-environment-collections-provider-regions' WHERE id=1`,
		`ALTER TABLE control.schema_identity ADD CONSTRAINT schema_identity_baseline_id_check CHECK (baseline_id='tnl-control-fresh-v1-explicit-capabilities-environment-collections-provider-regions')`,
	} {
		if _, err := d.pool.Exec(t.Context(), query); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := func() string {
		t.Helper()
		var result string
		if err := d.pool.QueryRow(t.Context(), `SELECT jsonb_build_array(
			(SELECT jsonb_agg(v ORDER BY id) FROM control.goose_db_version v),
			(SELECT to_jsonb(i) FROM control.schema_identity i WHERE id=1),
			(SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='control.schema_identity'::regclass AND conname='schema_identity_baseline_id_check'),
			to_regclass('control.workload_approvals') IS NULL,
			(SELECT to_jsonb(e) FROM control.environments e WHERE id=$1))::text`, environment.ID).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	before := snapshot()
	for _, check := range []struct {
		name string
		run  func() error
	}{
		{"migrate", func() error { return Migrate(t.Context(), url) }},
		{"readiness", func() error { return d.Readiness(t.Context()) }},
		{"open", func() error {
			opened, err := Open(t.Context(), url, testStorageKey, "", naming.ManagedURLModeGenerated)
			if opened != nil {
				opened.Close()
			}
			return err
		}},
	} {
		t.Run(check.name, func(t *testing.T) {
			err := check.run()
			if err == nil || !strings.Contains(err.Error(), "incompatible database baseline") || !strings.Contains(err.Error(), "use a fresh PostgreSQL database") {
				t.Errorf("pre-approval baseline rejection = %v; want a fresh-database diagnostic", err)
			}
			if snapshot() != before {
				t.Fatal("baseline check changed the predecessor identity, schema, or environment")
			}
		})
	}
}
