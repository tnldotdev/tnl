package state

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationServiceAuditActualGroupRemovalAndSafeAdminNormalization(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "audit_group_remove")
	d.managedURLMode = naming.ManagedURLModeSimple
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{
		"web":  {PublisherGroup: "production", Target: "http://audit-private-app.internal:3000"},
		"db":   {PublisherGroup: "production", Protocol: "postgres", Target: "audit-private-db.internal:5432"},
		"keep": {Target: "http://localhost:4000"},
	}}
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.IssuePublisherGroupEnrollment(t.Context(), r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedGroup(t, d, r, enrollment, now)
	public := createTestPublicURL(t, d, oidcRouteRequest(t, d, now), now).ID
	const secret = "never-copy-admin-details-key-csr-and-plaintext-configuration"
	if _, err = d.pool.Exec(t.Context(), `INSERT INTO control.admin_audit_events(actor_identity_id,actor,request_id,operation,target_kind,target_id,details,occurred_at) VALUES($1,$1,'audit-secret-regression','public_url.update','public_url',$2,$3,$4)`, r.ActorID, public, []byte(secret), now); err != nil {
		t.Fatal(err)
	}
	r.ExpectedRevision = applied.Revision
	delete(r.Configuration.PublisherGroups, "production")
	delete(r.Configuration.Services, "web")
	delete(r.Configuration.Services, "db")
	if _, err = d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal("actual group removal hit audit trigger ambiguity", err)
	}
	var revoked int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(DISTINCT service_id) FROM control.service_audit_events WHERE publisher_identity_id=$1 AND event_type='publisher.revoke'`, replica.member.PublisherIdentityID).Scan(&revoked); err != nil || revoked != 2 {
		t.Fatalf("removed group not audited across both kinds: %d %v", revoked, err)
	}
	page, err := d.ListServiceAudit(t.Context(), r.TeamID, r.ActorID, ServiceAuditFilter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(page)
	for _, value := range []string{secret, "audit-private-app.internal", "audit-private-db.internal", enrollment.Key} {
		if bytes.Contains(encoded, []byte(value)) {
			t.Fatal("audit copied sensitive management bytes")
		}
	}
}
