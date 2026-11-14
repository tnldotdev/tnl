package state

import (
	"testing"
	"time"
)

func TestIntegrationServicePortHistoryBaselinePreservesAuthority(t *testing.T) {
	d, directURL, now := newControlStateIntegrationDatabaseWithURL(t, "service_port_history_baseline")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"app": {Protocol: "tcp", Target: "localhost:3000", Public: new(true)},
		"old": {Protocol: "tcp", Target: "localhost:3001", Public: new(true)},
	}}
	r = selectedProjectRequest(r, "production")
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := testDeploymentPublisherEnrollment(d, ctx, r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedDeployment(t, d, r, enrollment, now)
	old := replica.assignments.Services[1]
	access := deploymentAssignmentAccess(t, d, replica, old, now)
	if _, err := d.PrepareServiceRun(ctx, old.ServiceID, access.PublisherIdentity, "before-retirement", now,
		ServiceMetadata{Protocol: old.Configuration.Protocol, TrustRevision: old.TrustRevision}); err != nil {
		t.Fatal(err)
	}
	r.ExpectedRevision = applied.Revision
	delete(r.Configuration.Services, "old")
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		t.Helper()
		var value string
		if err := d.pool.QueryRow(ctx, `SELECT jsonb_build_array(
		    (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM control.services s),
		    (SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM control.service_port_claims c),
		    (SELECT to_jsonb(i) FROM control.schema_identity i WHERE id=1))::text`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	if version, err := readSchemaVersion(ctx, d.pool); err != nil || version != 1 {
		t.Fatal("port history must use schema 1", version, err)
	}
	for range 2 {
		if err := Migrate(ctx, directURL); err != nil {
			t.Fatal(err)
		}
		if snapshot() != before {
			t.Fatal("repeat initialization changed identities or held/quarantined reservations")
		}
		if err := d.Readiness(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var held, quarantined int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE state='held' AND retired_run_number IS NULL),
	    count(*) FILTER(WHERE state='quarantined' AND retired_run_number=1 AND dns_cleared_at IS NULL)
	    FROM control.service_port_claims`).Scan(&held, &quarantined); err != nil || held != 1 || quarantined != 1 {
		t.Fatal("baseline lost the deletion fence", held, quarantined, err)
	}
}
