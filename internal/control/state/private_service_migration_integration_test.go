package state

import "testing"

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
}
