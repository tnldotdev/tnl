package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestIntegrationServiceMetadataCorruptionRollsBackCallers(t *testing.T) {
	d, now, _, leases := newPublishRunPrerequisites(t)
	ctx := t.Context()
	r := retainedEnvironmentProject(t, d, now)
	applied, _ := retainedServiceEnvironment(t, d, r, "production", map[string]EnvironmentServicePublication{"orders": {Protocol: "tcp", Target: "orders.internal:5432"}})
	localRequest := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "local", WorktreeKey: "checkout", ActorID: r.ActorID, Configuration: LocalServiceDeclaration{Protocol: "tcp", Target: "local.internal:5432"}, Now: now}
	local, err := d.RealizeLocalProjectService(ctx, localRequest)
	if err != nil {
		t.Fatal(err)
	}
	localLookup := GetLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "local", WorktreeKey: "checkout", ActorID: r.ActorID, Now: now}
	replica := enrollTestEnvironment(t, d, r, applied)
	assignment := replica.assignments.Services[0]
	access := environmentAssignmentAccess(t, d, replica, assignment, now)
	service, err := d.GetService(ctx, assignment.ServiceID, r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateServiceGrant(ctx, service.ID, r.ActorID, "metadata-owner", "identity", r.ActorID, nil, now); err != nil {
		t.Fatal(err)
	}
	run := readyAppliedServiceRun(t, d, access, replica.private, service, leases, now, &replica.assignments.Environment)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(ctx, r.ActorID, public, now)
	if err != nil {
		t.Fatal(err)
	}
	next := ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: applied.ID, ExpectedRevision: applied.MutationRevision, DefinitionRevision: applied.AppliedDefinitionRevision, Targets: EnvironmentTargets{"orders": {Address: "replacement.internal:5432"}}}, Now: now.Add(time.Second)}

	// failed reconciliation must roll back earlier run/grant changes, desired
	// configuration and audit, as well as the corrupt saved row.
	snapshot := func(t *testing.T) string {
		t.Helper()
		var data string
		if err := d.pool.QueryRow(ctx, `SELECT jsonb_build_array(
		    (SELECT jsonb_agg(to_jsonb(p) ORDER BY team_id,project_key) FROM control.applied_projects p),
		    (SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM control.environments e),
		    (SELECT jsonb_agg(to_jsonb(b) ORDER BY group_id) FROM control.publisher_group_bindings b),
		    (SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM control.project_publisher_groups g),
		    (SELECT jsonb_agg(to_jsonb(s) ORDER BY team_id,project_key,service) FROM control.applied_project_services s),
		    (SELECT jsonb_agg(to_jsonb(l) ORDER BY team_id,project_key,service,worktree_key) FROM control.local_project_services l),
		    (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM control.services s),
		    (SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM control.visitor_grants g),
		    (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM control.service_runs r),
		    (SELECT jsonb_agg(to_jsonb(s) ORDER BY publisher_connection_id) FROM control.service_connection_slots s),
		    (SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM control.publisher_grants g),
		    (SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM control.connector_peer_pairs p),
		    (SELECT jsonb_agg(to_jsonb(e) ORDER BY cursor) FROM control.service_audit_events e))::text`).Scan(&data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	for _, scope := range []struct{ name, id string }{{"local", local.ServiceID}, {"applied", service.ID}} {
		for _, tc := range []struct {
			name, encoded string
			valid, tls    bool
		}{
			{"absent", "", true, false}, {"null", "null", true, false},
			{"system trust", fmt.Sprintf(`{"hostname":"db.internal","system":true,"digest":%q}`, systemTrustDigest("db.internal")), true, true},
			{"wrong shape", `["sensitive trust"]`, false, false},
			{"invalid trust", `{"hostname":"db.internal","system":true,"pem":"sensitive trust","digest":"wrong"}`, false, false},
		} {
			t.Run(scope.name+"/"+tc.name, func(t *testing.T) {
				var encoded any
				if tc.encoded != "" {
					encoded = tc.encoded
				}
				if _, err := d.pool.Exec(ctx, `UPDATE control.services SET tls_metadata=$2::jsonb WHERE id=$1`, scope.id, encoded); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := d.pool.Exec(ctx, `UPDATE control.services SET tls_metadata=NULL WHERE id=$1`, scope.id); err != nil {
						t.Error(err)
					}
				}()
				before := snapshot(t)
				check := func(name string, err error) {
					t.Helper()
					if tc.valid {
						if err != nil {
							t.Fatalf("%s rejected valid stored trust: %v", name, err)
						}
					} else if !errors.Is(err, ErrServiceMetadata) || strings.Contains(err.Error(), "sensitive trust") {
						t.Fatalf("%s did not return a safe metadata corruption error: %v", name, err)
					}
				}
				record, err := d.GetService(ctx, scope.id, r.ActorID)
				check("saved service read", err)
				if tc.valid && (record.ID != scope.id || record.Protocol != "tcp" || (record.TLS != nil) != tc.tls) {
					t.Fatal("saved service read changed valid metadata")
				}
				if scope.name == "local" {
					got, err := d.GetLocalProjectService(ctx, localLookup)
					check("local visitor lookup", err)
					if tc.valid && (got.ServiceID != scope.id || got.Metadata == nil || got.Metadata.TLS != nil) {
						t.Fatal("local visitor lookup changed its trust-free output")
					}
					if !tc.valid {
						_, err := d.RealizeLocalProjectService(ctx, localRequest)
						check("local reconciliation", err)
					}
				} else {
					got, err := d.GetService(ctx, service.ID, r.ActorID)
					check("applied visitor lookup", err)
					if tc.valid && (got.ID != scope.id || (got.TLS != nil) != tc.tls) {
						t.Fatal("applied visitor lookup changed valid metadata")
					}
					selected, err := d.SelectServiceRun(ctx, scope.id, r.ActorID, device.ID, now)
					check("visitor run selection", err)
					if tc.valid && (selected.ServiceRunID != run.RunID || selected.RunNumber != run.RunNumber || (selected.TLS != nil) != tc.tls) {
						t.Fatal("visitor selection changed the saved run or trust")
					}
				}
				if !tc.valid && scope.name == "applied" {
					_, err := d.ApplyEnvironment(ctx, next)
					check("environment reconciliation", err)
				}
				if snapshot(t) != before {
					t.Fatal("metadata read or failed reconciliation committed transaction mutations")
				}
			})
		}
	}
}
