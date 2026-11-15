package state

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func policyObservation(t *testing.T, d *Database, scope visitorscope.Scope, after int64) controlv1.VisitorPolicyUpdate {
	t.Helper()
	tx, err := d.pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	result, err := d.readVisitorPolicy(t.Context(), tx, scope, after, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return result
}

func policyRevision(t *testing.T, d *Database, scope visitorscope.Scope) int64 {
	t.Helper()
	revision, err := controlstatedb.New(d.pool).ReadVisitorPolicyRevision(t.Context(), scope.ID)
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

func TestIntegrationVisitorPolicyPreservesSavedIPAllowlist(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_policy_saved_ip")
	session := newOIDCSession(t, d, now)
	team := session.Identity.Memberships[0].TeamID
	actor := session.Identity.Identity.ID
	ctx := WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: actor, SessionID: session.SessionID})
	service, err := d.CreateServiceAt(ctx, team, actor, "web", "web", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"},
		&ProjectServiceConfiguration{Target: "localhost:3000", HTTP: &config.HTTPService{Access: &config.Access{Mode: "restricted", IP: []string{"192.0.2.0/24"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	update, err := visitorlease.Decode(policyObservation(t, d, visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}, 0))
	if err != nil || update.IP == nil || !update.IP.Allows(netip.MustParseAddr("192.0.2.7")) || update.IP.Allows(netip.MustParseAddr("198.51.100.7")) {
		t.Fatal("saved IP allowlist was not retained in the policy snapshot", err)
	}
}

func TestIntegrationVisitorPolicyMutationsCommitWithTheirScopeHistory(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_policy_mutations")
	session := newOIDCSession(t, d, now)
	team := session.Identity.Memberships[0].TeamID
	actor := session.Identity.Identity.ID
	ctx := WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: actor, SessionID: session.SessionID})
	service, err := d.CreateServiceAt(ctx, team, actor, "web", "web", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}
	before := policyRevision(t, d, scope)
	tx, err := d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	if _, err := tx.Exec(t.Context(), `SELECT control.touch_visitor_policy($1)`, service.ID); err != nil {
		t.Fatal(err)
	}
	inside, err := controlstatedb.New(tx).ReadVisitorPolicyRevision(t.Context(), service.ID)
	if err != nil || inside <= before {
		t.Fatal("permission mutation did not record invalidation in its transaction", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if policyRevision(t, d, scope) != before {
		t.Fatal("rolled-back permission change leaked an invalidation")
	}
	if _, err := d.pool.Exec(t.Context(), `SELECT control.touch_visitor_policy($1)`, service.ID); err != nil {
		t.Fatal(err)
	}
	after := policyRevision(t, d, scope)
	if after <= before {
		t.Fatal("committed permission change did not advance visitor policy")
	}
	events, err := controlstatedb.New(d.pool).ReadVisitorPolicyEvents(t.Context(), controlstatedb.ReadVisitorPolicyEventsParams{ResourceID: service.ID, AfterRevision: before})
	if err != nil || len(events) != int(after-before) {
		t.Fatal("policy revision did not cover its committed events", err)
	}
	for index, event := range events {
		if event.Revision != before+int64(index)+1 {
			t.Fatal("policy history has a gap")
		}
	}
}

func TestIntegrationVisitorPolicyIdentityRevocationCancelsPreparedTraffic(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_policy_revoke")
	session := newOIDCSession(t, d, now)
	principal := ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID}
	ctx := WithControlPrincipal(t.Context(), principal)
	service, err := d.CreateServiceAt(ctx, session.Identity.Memberships[0].TeamID, principal.IdentityID, "web", "web", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}
	issued, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, BrowserTokenSource{}, now)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := visitorlease.New(scope, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	first := lease.Begin()
	update, err := visitorlease.Decode(policyObservation(t, d, scope, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Apply(first, update); err != nil {
		t.Fatal(err)
	}
	view, enabled, _ := lease.Current()
	if !enabled {
		t.Fatal("prepared policy was disabled")
	}
	permission, err := visitortoken.VerifyBearer(issued.Token, view, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var stopped atomic.Int64
	guard, err := lease.Bind(permission, netip.MustParseAddr("192.0.2.1"), func() { stopped.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, principal.IdentityID, time.Now()); err != nil {
		t.Fatal(err)
	}
	next := lease.Begin()
	update, err = visitorlease.Decode(policyObservation(t, d, scope, next.AfterRevision))
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Apply(next, update); err != nil {
		t.Fatal(err)
	}
	if stopped.Load() != 1 {
		t.Fatal("applied revocation retained active traffic")
	}
	view, _, _ = lease.Current()
	if _, err := visitortoken.VerifyBearer(issued.Token, view, time.Now()); !errors.Is(err, visitortoken.ErrToken) {
		t.Fatal("prepared admission accepted a revoked token", err)
	}
}

func TestIntegrationVisitorPolicyCompactionAndKeyRotationHaveIndependentVersions(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_policy_history")
	session := newOIDCSession(t, d, now)
	principal := ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID}
	ctx := WithControlPrincipal(t.Context(), principal)
	service, err := d.CreateServiceAt(ctx, session.Identity.Memberships[0].TeamID, principal.IdentityID, "web", "web", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	first := policyObservation(t, d, scope, 0)
	if !first.SnapshotRequired || len(first.Policy.VerificationKeys) != 1 {
		t.Fatal("initial policy was not a complete key-bearing snapshot")
	}
	if err := d.RotateVisitorSigningKey(t.Context(), testVisitorIssuer, false, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	rotated := policyObservation(t, d, scope, first.Policy.VisitorPolicyRevision)
	if rotated.Policy.VisitorPolicyRevision != first.Policy.VisitorPolicyRevision || rotated.Policy.KeyRevision <= first.Policy.KeyRevision {
		t.Fatal("signing-key rotation reused a resource permission revision")
	}
	if _, err := d.pool.Exec(t.Context(), `SELECT control.touch_visitor_policy($1) FROM generate_series(1,300)`, service.ID); err != nil {
		t.Fatal(err)
	}
	compacted := policyObservation(t, d, scope, first.Policy.VisitorPolicyRevision)
	if !compacted.SnapshotRequired || len(compacted.Revisions) != 0 || compacted.Policy.VisitorPolicyRevision <= rotated.Policy.VisitorPolicyRevision {
		t.Fatal("compacted history extended authority without a snapshot")
	}
	var count int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.visitor_policy_events WHERE resource_id=$1`, service.ID).Scan(&count); err != nil || count != 256 {
		t.Fatal("policy event retention escaped its per-scope bound", err)
	}
}
