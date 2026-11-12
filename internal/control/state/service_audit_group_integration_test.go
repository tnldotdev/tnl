package state

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationServiceAuditActualGroupRemovalAndSafeAdminNormalization(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "audit_group_remove")
	d.managedURLMode = naming.ManagedURLModeSimple
	r := retainedEnvironmentProject(t, d, now)
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"web": {Protocol: "http"}, "db": {Protocol: "postgres"}})
	applied, _ := createTestEnvironment(t, d, r, "production", definition.Revision, EnvironmentTargets{"web": {Address: "audit-private-app.internal:3000"}, "db": {Address: "audit-private-db.internal:5432"}})
	local, err := d.RealizeLocalProjectService(t.Context(), RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, ActorID: r.ActorID, Service: "keep", WorktreeKey: "checkout", Configuration: LocalServiceDeclaration{Target: "http://localhost:4000"}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollTestEnvironment(t, d, r, applied)
	public := createTestPublicURL(t, d, oidcRouteRequest(t, d, now), now).ID
	const secret = "never-copy-admin-details-key-csr-and-plaintext-configuration"
	if _, err = d.pool.Exec(t.Context(), `INSERT INTO control.admin_audit_events(actor_identity_id,actor,request_id,operation,target_kind,target_id,details,occurred_at) VALUES($1,$1,'audit-secret-regression','public_url.update','public_url',$2,$3,$4)`, r.ActorID, public, []byte(secret), now); err != nil {
		t.Fatal(err)
	}
	if err = d.RetireEnvironment(t.Context(), RetireEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentID: applied.ID, ExpectedRevision: applied.MutationRevision, Now: now}); err != nil {
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
	for _, value := range []string{secret, "audit-private-app.internal", "audit-private-db.internal", replica.enrollment.Key} {
		if bytes.Contains(encoded, []byte(value)) {
			t.Fatal("audit copied sensitive management bytes")
		}
	}
	if saved, err := d.GetService(t.Context(), local.ServiceID, r.ActorID); err != nil || !saved.Enabled {
		t.Fatal("environment retirement swept a local service", err)
	}
}
