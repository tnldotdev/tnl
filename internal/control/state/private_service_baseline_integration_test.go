package state

import (
	"io/fs"
	"testing"
)

func TestIntegrationPrivateServiceBaselinePreservesReservations(t *testing.T) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "00001_baseline.sql" || schemaVersion != 1 || baselineID != "v1" {
		t.Fatal("private services must use the single v1 baseline")
	}
	d, directURL, now := newControlStateIntegrationDatabaseWithURL(t, "private_port_baseline")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{Public: true}, Services: map[string]ProjectServiceConfiguration{
		"orders": {Protocol: "postgres", Target: "localhost:5432"},
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
			(SELECT to_jsonb(p) FROM control.service_port_claims p WHERE service_id=$1),
			(SELECT to_jsonb(i) FROM control.schema_identity i WHERE id=1))::text`, service.ServiceID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	if version, err := readSchemaVersion(ctx, d.pool); err != nil || version != 1 {
		t.Fatal("fixture did not initialize schema 1", version, err)
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
}
