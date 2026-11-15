package state

import (
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationServiceSuspensionClosesRunsWithoutReplacingAuthority(t *testing.T) {
	f := newServiceHTTPFixture(t)
	d, ctx := f.database, t.Context()
	var err error
	f.service, err = d.CreateServiceAt(ctx, f.project.TeamID, f.project.ActorID, "suspend", "suspend",
		ServicePlacement{}, f.now, ServiceMetadata{Protocol: "http", PublisherPool: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, second := f.publish(t, f.service), f.publish(t, f.service)
	before, digest, err := d.GetServiceConfiguration(ctx, f.service.ID, f.project.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	var grants int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.publisher_grants WHERE service_id=$1 AND revoked_at IS NULL`, f.service.ID).Scan(&grants); err != nil || grants != 2 {
		t.Fatal("fixture did not retain both exact publisher grants", grants, err)
	}
	policy := controlstatedb.ReadVisitorPolicyRevisionParams{ResourceKind: "service", ResourceID: f.service.ID}
	q := controlstatedb.New(d.pool)
	revision, err := q.ReadVisitorPolicyRevision(ctx, policy)
	if err != nil {
		t.Fatal(err)
	}
	suspended, err := d.SetServiceEnabled(ctx, f.service.ID, f.project.ActorID, false, f.now)
	if err != nil || suspended.Enabled || suspended.ID != f.service.ID ||
		suspended.TrustRevision != f.service.TrustRevision || suspended.EndpointRevision != f.service.EndpointRevision ||
		!reflect.DeepEqual(suspended.Endpoint, f.service.Endpoint) {
		t.Fatal("suspension replaced the saved service or its endpoint/trust", err)
	}
	var live, slots, retainedGrants int
	if err := d.pool.QueryRow(ctx, `SELECT
	    (SELECT count(*) FROM control.service_runs WHERE service_id=$1 AND closed_at IS NULL),
	    (SELECT count(*) FROM control.service_connection_slots WHERE service_id=$1 AND session_open),
	    (SELECT count(*) FROM control.publisher_grants WHERE service_id=$1 AND revoked_at IS NULL)`,
		f.service.ID).Scan(&live, &slots, &retainedGrants); err != nil || live != 0 || slots != 0 || retainedGrants != grants {
		t.Fatal("suspension retained live runs/slots or revoked saved grants", live, slots, retainedGrants, err)
	}
	changed, err := q.ReadVisitorPolicyRevision(ctx, policy)
	if err != nil || changed <= revision {
		t.Fatal("suspension did not invalidate visitor policy", changed, revision, err)
	}
	if _, err := d.SetServiceEnabled(ctx, f.service.ID, f.project.ActorID, false, f.now); err != nil {
		t.Fatal("suspension retry failed", err)
	}
	retried, err := q.ReadVisitorPolicyRevision(ctx, policy)
	if err != nil || retried != changed {
		t.Fatal("unchanged suspension invalidated policy again", err)
	}
	enabled, err := d.SetServiceEnabled(ctx, f.service.ID, f.project.ActorID, true, f.now)
	if err != nil || !enabled.Enabled || enabled.ID != f.service.ID ||
		enabled.TrustRevision != f.service.TrustRevision || enabled.EndpointRevision != f.service.EndpointRevision {
		t.Fatal("enable did not preserve the saved service", err)
	}
	after, afterDigest, err := d.GetServiceConfiguration(ctx, f.service.ID, f.project.ActorID)
	if err != nil || digest != afterDigest || !reflect.DeepEqual(before, after) {
		t.Fatal("availability changed saved intent", err)
	}
	for _, run := range []ServiceRunState{first, second} {
		if _, err := d.HeartbeatServiceRun(ctx, run.ServiceID, run.RunID, run.Token, f.now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("enable revived a closed run", err)
		}
	}
	next := f.publish(t, enabled)
	if next.ServiceID != f.service.ID || next.RunNumber <= second.RunNumber || next.RunID == first.RunID || next.RunID == second.RunID {
		t.Fatal("enable did not permit a new ordinary service run")
	}
}

func TestIntegrationServiceAvailabilityUsesStoredManagementWithoutEditingProjects(t *testing.T) {
	f := newServiceManagementFixture(t)
	ctx := t.Context()
	for _, service := range []ServiceRecord{f.local, f.allocation} {
		grant, err := f.d.CreateServiceGrant(ctx, service.ID, f.member.IdentityID, "suspend/"+service.ID, "identity", f.unrelated.IdentityID, nil, f.now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.d.SetServiceEnabled(ctx, service.ID, f.unrelated.IdentityID, false, f.now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("unrelated member suspended another member's service", err)
		}
		if _, err := f.d.SetServiceEnabled(ctx, service.ID, f.publisher.ID, false, f.now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("publisher identity gained management authority", err)
		}
		if _, err := f.d.SetServiceEnabled(ctx, service.ID, f.member.IdentityID, false, f.now); err != nil {
			t.Fatal("stored owner could not suspend its service", err)
		}
		if err := f.d.RevokeServiceGrant(ctx, service.ID, f.member.IdentityID, grant.ID, f.now); err != nil {
			t.Fatal("suspension prevented revocation", err)
		}
		if _, err := f.d.SetServiceEnabled(ctx, service.ID, f.unrelated.IdentityID, true, f.now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("disabled service lost its ownership check", err)
		}
		if _, err := f.d.SetServiceEnabled(ctx, service.ID, f.member.IdentityID, true, f.now); err != nil {
			t.Fatal("stored owner could not re-enable its service", err)
		}
		grants, _, err := f.d.ListServiceGrants(ctx, service.ID, f.member.IdentityID, "")
		index := slices.IndexFunc(grants, func(current ServiceGrant) bool { return current.ID == grant.ID })
		if err != nil || index < 0 || grants[index].RevokedAt == nil {
			t.Fatal("enabling restored revoked visitor permission", err)
		}
	}
	managed := newServiceHTTPFixture(t)
	before, digest, err := managed.database.GetServiceConfiguration(ctx, managed.service.ID, managed.project.ActorID)
	if err != nil || before == nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{false, true} {
		if _, err := managed.database.SetServiceEnabled(ctx, managed.service.ID, managed.project.ActorID, enabled, managed.now); err != nil {
			t.Fatal("operational availability required editing a managed declaration", err)
		}
	}
	after, afterDigest, err := managed.database.GetServiceConfiguration(ctx, managed.service.ID, managed.project.ActorID)
	if err != nil || digest != afterDigest || !reflect.DeepEqual(before, after) {
		t.Fatal("operational availability replaced project intent", err)
	}
}

func TestIntegrationServiceEnableDoesNotRestoreDeletedOrExpiredServices(t *testing.T) {
	f := newServiceManagementFixture(t)
	ctx := t.Context()
	if _, err := f.d.SetServiceEnabled(ctx, f.local.ID, f.member.IdentityID, false, f.now); err != nil {
		t.Fatal(err)
	}
	if err := f.d.DeleteService(ctx, f.local.ID, f.member.IdentityID, f.now); err != nil {
		t.Fatal("suspension prevented saved-service cleanup", err)
	}
	if _, err := f.d.SetServiceEnabled(ctx, f.local.ID, f.member.IdentityID, true, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("enabling restored a deleted service", err)
	}
	if _, err := f.d.SetServiceEnabled(ctx, f.allocation.ID, f.member.IdentityID, false, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.pool.Exec(ctx, `UPDATE control.services SET expires_at=$2 WHERE id=$1`, f.allocation.ID, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.SetServiceEnabled(ctx, f.allocation.ID, f.member.IdentityID, true, f.now.Add(2*time.Second)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("enabling extended an expired service", err)
	}
}
