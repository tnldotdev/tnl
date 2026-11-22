package state

import (
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationPrivateServiceMigrationPreservesReservations(t *testing.T) {
	d, directURL, now := newControlStateIntegrationDatabaseWithURL(t, "private_port_migration")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"orders": {Protocol: "postgres", Target: "localhost:5432", Public: new(true)},
	}}
	r = selectedProjectRequest(r, "production")
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	service := applied.Services[0]
	snapshot := func() string {
		t.Helper()
		var value string
		if err := d.pool.QueryRow(ctx, `SELECT jsonb_build_array(
			(SELECT to_jsonb(s) FROM control.services s WHERE id=$1),
			(SELECT to_jsonb(p) FROM control.service_port_claims p WHERE service_id=$1))::text`, service.ServiceID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	if version, err := readSchemaVersion(ctx, d.pool); err != nil || version != schemaVersion {
		t.Fatal("fixture did not initialize the current schema", version, err)
	}
	for range 2 {
		if err := Migrate(ctx, directURL); err != nil {
			t.Fatal(err)
		}
		if err := d.Readiness(ctx); err != nil {
			t.Fatal(err)
		}
		if snapshot() != before {
			t.Fatal("repeat initialization changed service identity or a reserved public port")
		}
	}
	rejected := func(op string, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "incompatible version 1 database schema") {
			t.Fatalf("%s accepted the older watch schema or failed for another reason: %v", op, err)
		}
	}
	for _, prior := range []string{
		// the unscoped bookmark view did not read the service's connect selection.
		`CREATE OR REPLACE VIEW control.service_policy_watch_bookmarks AS
		 SELECT id AS service_id, ''::text AS bookmark FROM control.services`,
		// the earlier publisher watch did not have run-scoped bookmarks either.
		`DROP VIEW control.publisher_run_policy_bookmarks;
		 ALTER VIEW control.service_policy_watch_bookmarks RENAME TO publisher_policy_watch_bookmarks;
		 DROP TABLE control.run_alias_watch_versions`,
	} {
		if _, err := d.pool.Exec(ctx, prior); err != nil {
			t.Fatal(err)
		}
		rejected("migrate", Migrate(ctx, directURL))
		rejected("readiness", d.Readiness(ctx))
		old, err := Open(ctx, directURL, testStorageKey, "", naming.ManagedURLModeGenerated)
		if old != nil {
			old.Close()
		}
		rejected("open", err)
		if version, err := readSchemaVersion(ctx, d.pool); err != nil || version != 1 || snapshot() != before {
			t.Fatal("rejection changed the version, service, or reservation", err)
		}
	}
}
