package state

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func policyObservation(t *testing.T, d *Database, scope visitorscope.Scope, after int64) controlv1.VisitorPolicyUpdate {
	t.Helper()
	return policyObservationAt(t, d, scope, after, time.Now())
}

func policyObservationAt(t *testing.T, d *Database, scope visitorscope.Scope, after int64, now time.Time) controlv1.VisitorPolicyUpdate {
	t.Helper()
	tx, err := d.pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	result, err := d.readVisitorPolicy(t.Context(), tx, scope, after, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestIntegrationVisitorPolicyProjectsCurrentIPAuthority(t *testing.T) {
	for _, representation := range []string{"encrypted", "hashed", "live-grants"} {
		t.Run(representation, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "visitor_policy_ip")
			request := oidcRouteRequest(t, d, now)
			request.AccessMode = VisitorAccessAnonymous
			request.AllowedIPPrefixes = []string{"192.0.2.0/24", "2001:db8::/32"}
			url := createTestPublicURL(t, d, request, now)
			if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
				t.Fatal(err)
			}
			until := now.Add(5 * time.Second)
			switch representation {
			case "hashed":
				// guest policies retain the keyed projection without recoverable prefixes.
				if _, err := d.pool.Exec(t.Context(), `UPDATE control.public_urls SET allowed_ip_policy_ciphertext=NULL,allowed_ip_policy_storage_key_id=NULL WHERE id=$1`, url.ID); err != nil {
					t.Fatal(err)
				}
			case "live-grants":
				if _, err := d.MutateVisitorIPs(t.Context(), url.ID, request.ActingIdentityID, "set", "", []VisitorIPGrantInput{{Prefix: "192.0.2.0/24", ExpiresAt: &until}, {Prefix: "2001:db8::/32", ExpiresAt: &until}}, now); err != nil {
					t.Fatal(err)
				}
			}
			scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}
			check := func(at time.Time, allowed bool) {
				t.Helper()
				wire := policyObservationAt(t, d, scope, 0, at)
				if representation == "live-grants" && at.Before(until) && !wire.Policy.ValidUntil.Equal(until) {
					t.Fatal("policy outlived its expiring IP grants")
				}
				update, err := visitorlease.Decode(wire)
				if err != nil {
					t.Fatal(err)
				}
				lease, err := visitorlease.New(scope, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer lease.Close()
				if err := lease.Apply(lease.Begin(), update); err != nil {
					t.Fatal(err)
				}
				for _, source := range []string{"192.0.2.7", "2001:db8::7", "198.51.100.7", "2001:db9::7"} {
					guard, err := lease.BindAnonymous(netip.MustParseAddr(source), func() {})
					want := allowed && (source == "192.0.2.7" || source == "2001:db8::7")
					if (err == nil) != want {
						t.Fatalf("%s allowed=%v, want %v: %v", source, err == nil, want, err)
					}
					if guard != nil {
						guard.Close()
					}
				}
			}
			check(now, true)
			if representation == "live-grants" {
				check(until, false)
			} else {
				// initializing an empty live set must not restore the saved allowlist.
				if err := controlstatedb.New(d.pool).MarkVisitorIPSet(t.Context(), url.ID); err != nil {
					t.Fatal(err)
				}
				check(now, false)
			}
		})
	}
}

func policyRevision(t *testing.T, d *Database, scope visitorscope.Scope) int64 {
	t.Helper()
	revision, err := controlstatedb.New(d.pool).ReadVisitorPolicyRevision(t.Context(), controlstatedb.ReadVisitorPolicyRevisionParams{ResourceKind: string(scope.Kind), ResourceID: scope.ID})
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

func TestIntegrationVisitorPolicyMutationsCommitWithTheirScopeHistory(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_policy_mutations")
	request := oidcRouteRequest(t, d, now)
	url := createTestPublicURL(t, d, request, now)
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}
	before := policyRevision(t, d, scope)
	tx, err := d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE control.public_urls SET access_mode='anonymous' WHERE id=$1`, url.ID); err != nil {
		t.Fatal(err)
	}
	inside, err := controlstatedb.New(tx).ReadVisitorPolicyRevision(t.Context(), controlstatedb.ReadVisitorPolicyRevisionParams{ResourceKind: "public_url", ResourceID: url.ID})
	if err != nil || inside <= before {
		t.Fatal("permission mutation did not record invalidation in its transaction", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if policyRevision(t, d, scope) != before {
		t.Fatal("rolled-back permission change leaked an invalidation")
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.public_urls SET access_mode='anonymous' WHERE id=$1`, url.ID); err != nil {
		t.Fatal(err)
	}
	after := policyRevision(t, d, scope)
	if after <= before {
		t.Fatal("committed permission change did not advance visitor policy")
	}
	events, err := controlstatedb.New(d.pool).ReadVisitorPolicyEvents(t.Context(), controlstatedb.ReadVisitorPolicyEventsParams{ResourceKind: "public_url", ResourceID: url.ID, AfterRevision: before})
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
	request := oidcRouteRequest(t, d, now)
	url := createTestPublicURL(t, d, request, now)
	session := newOIDCSession(t, d, now)
	ctx := WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID})
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}
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
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, request.ActingIdentityID, time.Now()); err != nil {
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
	request := oidcRouteRequest(t, d, now)
	url := createTestPublicURL(t, d, request, now)
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}
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
	if _, err := d.pool.Exec(t.Context(), `SELECT control.touch_visitor_policy('public_url',$1) FROM generate_series(1,300)`, url.ID); err != nil {
		t.Fatal(err)
	}
	compacted := policyObservation(t, d, scope, first.Policy.VisitorPolicyRevision)
	if !compacted.SnapshotRequired || len(compacted.Revisions) != 0 || compacted.Policy.VisitorPolicyRevision <= rotated.Policy.VisitorPolicyRevision {
		t.Fatal("compacted history extended authority without a snapshot")
	}
	var count int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.visitor_policy_events WHERE resource_kind='public_url' AND resource_id=$1`, url.ID).Scan(&count); err != nil || count != 256 {
		t.Fatal("policy event retention escaped its per-scope bound", err)
	}
}

func TestIntegrationIngressVisitorPolicyRequiresExactLeaseAndPool(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_policy_ingress")
	request := oidcRouteRequest(t, d, now)
	url := createTestPublicURL(t, d, request, now)
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	lease, err := d.RegisterIngress(t.Context(), IngressRegistration{IngressID: "policy-ingress", IngressRunID: "policy-run", ProtocolVersion: 1, ConnectionCapacity: 10, IngressPoolID: PrimaryIngressPoolID}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}
	if _, err := d.ReadIngressVisitorPolicy(t.Context(), lease.IngressLeaseIdentity, scope, 0, now); err != nil {
		t.Fatal(err)
	}
	wrong := lease.IngressLeaseIdentity
	wrong.IngressRunID = "restarted"
	if _, err := d.ReadIngressVisitorPolicy(t.Context(), wrong, scope, 0, now); err == nil {
		t.Fatal("old process identity read visitor policy")
	}
	if _, err := d.ReadIngressVisitorPolicy(context.Background(), lease.IngressLeaseIdentity, scope, 0, now.Add(time.Minute)); err == nil {
		t.Fatal("expired process lease read fresh visitor policy")
	}
}
