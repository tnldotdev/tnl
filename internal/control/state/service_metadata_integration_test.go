package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"
)

func TestIntegrationServiceMetadataCorruptionRollsBackCallers(t *testing.T) {
	d, now, _, leases := newPublishRunPrerequisites(t)
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{
		"orders": {PublisherGroup: "production", Protocol: "tcp", Target: "orders.internal:5432"},
		"local":  {Protocol: "tcp", Target: "local.internal:5432"},
	}}
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	localRequest := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "local", WorktreeKey: "checkout", ActorID: r.ActorID, Configuration: applied.Configuration.Services["local"], Now: now}
	local, err := d.RealizeLocalProjectService(ctx, localRequest)
	if err != nil {
		t.Fatal(err)
	}
	localLookup := GetLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "local", WorktreeKey: "checkout", ActorID: r.ActorID, Now: now}
	enrollment, err := d.IssuePublisherGroupEnrollment(ctx, r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedGroup(t, d, r, enrollment, now)
	assignment := replica.assignments.Services[0]
	access := groupAssignmentAccess(t, d, replica, assignment, now)
	service, err := d.GetService(ctx, assignment.ServiceID, r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	run := readyAppliedServiceRun(t, d, access, replica.private, service, leases, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(ctx, r.ActorID, public, now)
	if err != nil {
		t.Fatal(err)
	}
	projectLookup := GetProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "orders", IdentityID: r.ActorID, Now: now}
	next := r
	next.ExpectedRevision, next.Now = applied.Revision, now.Add(time.Second)
	next.Configuration = applied.Configuration
	next.Configuration.Services = maps.Clone(applied.Configuration.Services)
	orders := next.Configuration.Services["orders"]
	orders.Target = "replacement.internal:5432"
	next.Configuration.Services["orders"] = orders

	// failed reconciliation must roll back earlier run/grant changes, desired
	// configuration and audit, as well as the corrupt saved row.
	snapshot := func(t *testing.T) string {
		t.Helper()
		var data string
		if err := d.pool.QueryRow(ctx, `SELECT jsonb_build_array(
		    (SELECT jsonb_agg(to_jsonb(p) ORDER BY team_id,project_key) FROM control.applied_projects p),
		    (SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM control.project_publisher_groups g),
		    (SELECT jsonb_agg(to_jsonb(s) ORDER BY team_id,project_key,service) FROM control.applied_project_services s),
		    (SELECT jsonb_agg(to_jsonb(l) ORDER BY team_id,project_key,service,worktree_key) FROM control.local_project_services l),
		    (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM control.services s),
		    (SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM control.visitor_grants g),
		    (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM control.service_runs r),
		    (SELECT jsonb_agg(to_jsonb(s) ORDER BY publisher_connection_id) FROM control.service_connection_slots s),
		    (SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM control.publisher_grants g),
		    (SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM control.native_peer_pairs p),
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
					got, err := d.GetProjectService(ctx, projectLookup)
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
				if !tc.valid {
					_, err := d.ApplyProjectConfiguration(ctx, next)
					check("applied reconciliation", err)
				}
				if snapshot(t) != before {
					t.Fatal("metadata read or failed reconciliation committed transaction mutations")
				}
			})
		}
	}
}
