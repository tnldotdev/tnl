package state

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationGuestAuthorityClipsEveryIssuedHorizon(t *testing.T) {
	for _, credentialBound := range []bool{false, true} {
		t.Run(map[bool]string{false: "remaining-ready", true: "credential-expiry"}[credentialBound], func(t *testing.T) {
			db, now, request, _ := newPublishRunPrerequisites(t)
			guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
			if err != nil {
				t.Fatal(err)
			}
			domainID, err := db.CreateGuestTrial(t.Context(), guest, "routes.example.test", now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.EnsureGuestPrincipal(t.Context(), guest.ID, now); err != nil {
				t.Fatal(err)
			}
			if _, err := db.AllocateGuestDemoNumber(t.Context(), guest.ID, now); err != nil {
				t.Fatal(err)
			}
			url := createTestPublicURL(t, db, CreatePublicURLRequest{GuestID: guest.ID, TeamID: guest.TeamID, DomainID: domainID, MembershipID: guest.MembershipID,
				ActingIdentityID: guest.ID, IdempotencyKey: "guest-url", CanonicalHostname: "demo-1." + guest.NamespaceLabel + ".routes.example.test", Target: "http://127.0.0.1:3000",
				PublicURLScope: PublicURLScopeMember, Purpose: PublicURLPurposeDemo, AllowedIPPrefixes: []string{"192.0.2.7/32"}, DNSState: PublicURLDNSUnmanaged, PolicyRevision: 1, Ephemeral: true}, now)
			request.GuestID, request.PublicURLID, request.TeamID, request.MembershipID = guest.ID, url.ID, guest.TeamID, guest.MembershipID
			request.ActingIdentityID, request.CertificateIdentifiers = guest.ID, []string{url.CanonicalHostname}
			request.ExpectedMutationRevision = url.MutationRevision
			if _, err := db.pool.Exec(t.Context(), `UPDATE control.guest_trials SET used_ready_ns=$2 WHERE id=$1`, guest.ID, int64(GuestReadyAllowance-5*time.Second)); err != nil {
				t.Fatal(err)
			}
			deadline := now.Add(5 * time.Second)
			if credentialBound {
				deadline = now.Add(4 * time.Second)
				if _, err := db.pool.Exec(t.Context(), `UPDATE control.guest_trials SET expires_at=$2 WHERE id=$1`, guest.ID, deadline); err != nil {
					t.Fatal(err)
				}
			}
			setup, err := db.CreatePublishRun(t.Context(), request, now, time.Hour, time.Minute)
			if err != nil || !setup.ExpiresAt.Equal(deadline) {
				t.Fatalf("preparation publisher horizon = %v, %v", setup.ExpiresAt, err)
			}
			if err := db.PrepareVisitorSigningKeys(t.Context(), "https://control.example.test", now); err != nil {
				t.Fatal(err)
			}
			ingress, err := db.RegisterIngress(t.Context(), IngressRegistration{IngressID: "guest-policy", IngressRunID: "guest-policy-run", ProtocolVersion: 1, ConnectionCapacity: 10, IngressPoolID: PrimaryIngressPoolID}, now, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}
			policy, err := db.ReadIngressVisitorPolicy(t.Context(), ingress.IngressLeaseIdentity, scope, 0, now)
			if err != nil || !policy.Policy.ValidUntil.Equal(deadline) {
				t.Fatalf("preparation policy = %v, %v", policy.Policy.ValidUntil, err)
			}
			allocationRequest := StreamCapacityRequest{Owner: ingress.IngressLeaseIdentity, Scope: scope, RunID: setup.PublishRunID, RunNumber: int64(setup.PublishRunNumber), RequestID: "guest-allocation", Capacity: 1}
			allocation, err := db.AllocateStreamCapacity(t.Context(), allocationRequest, now)
			if err != nil || !allocation.ValidUntil.Equal(deadline) {
				t.Fatalf("preparation allocation = %v, %v", allocation.ValidUntil, err)
			}
			q := controlstatedb.New(db.pool)
			if count, err := q.MarkGuestRunReady(t.Context(), controlstatedb.MarkGuestRunReadyParams{PublishRunID: text(setup.PublishRunID), ReadyAt: timestamptz(now)}); err != nil || count != 1 {
				t.Fatalf("mark guest ready = %d, %v", count, err)
			}
			secret := sha256.Sum256([]byte("guest share secret"))
			share, err := db.CreateGuestShare(t.Context(), guest.ID, url.ID, "guest-share", "", sha256.Sum256(secret[:]), now.Add(time.Hour), now)
			if err != nil {
				t.Fatal(err)
			}
			source := ShareTokenSource{ShareID: share.ID, Secret: base64.RawURLEncoding.EncodeToString(secret[:])}
			authentication := PublishRunAuthentication{PublicURLID: url.ID, PublishRunID: setup.PublishRunID, PublishRunNumber: setup.PublishRunNumber, PublishRunToken: setup.PublishRunToken}
			for _, elapsed := range []time.Duration{time.Second, 3 * time.Second} {
				at := now.Add(elapsed)
				renewed, err := db.HeartbeatPublishRun(t.Context(), authentication, at, time.Hour, time.Minute)
				if err != nil || !renewed.ExpiresAt.Equal(deadline) {
					t.Fatalf("ready publisher horizon = %v, %v", renewed.ExpiresAt, err)
				}
				publisherPolicy, err := db.ReadPublisherVisitorPolicy(t.Context(), scope, setup.PublishRunID, int64(setup.PublishRunNumber), setup.PublishRunToken.String(), 0, nil, at)
				if err != nil || !publisherPolicy.Policy.ValidUntil.Equal(deadline) {
					t.Fatalf("publisher policy = %v, %v", publisherPolicy.Policy.ValidUntil, err)
				}
				ingressPolicy, err := db.ReadIngressVisitorPolicy(t.Context(), ingress.IngressLeaseIdentity, scope, 0, at)
				if err != nil || !ingressPolicy.Policy.ValidUntil.Equal(deadline) {
					t.Fatalf("ingress policy = %v, %v", ingressPolicy.Policy.ValidUntil, err)
				}
				allocation, err := db.AllocateStreamCapacity(t.Context(), allocationRequest, at)
				if err != nil || !allocation.ValidUntil.Equal(deadline) {
					t.Fatalf("renewed allocation = %v, %v", allocation.ValidUntil, err)
				}
				token, err := db.IssueVisitorToken(t.Context(), "https://control.example.test", scope, source, at)
				if err != nil || !token.Permission.ExpiresAt.Equal(deadline) {
					t.Fatalf("signed permission deadline = %v, %v", token.Permission.ExpiresAt, err)
				}
			}
			if _, err := db.IssueVisitorToken(t.Context(), "https://control.example.test", scope, source, deadline); !errors.Is(err, ErrVisitorPermission) {
				t.Fatalf("expired share renewed authority: %v", err)
			}
			invalid := authentication
			invalid.PublishRunToken = "invalid"
			if _, err := db.HeartbeatPublishRun(t.Context(), invalid, deadline, time.Hour, time.Minute); !errors.Is(err, ErrPublishRunCredential) {
				t.Fatalf("unauthenticated expiry settled guest authority: %v", err)
			}
			stored, err := db.GuestTrialByAccessToken(t.Context(), guest.Token)
			if err != nil || stored.UsedReady != GuestReadyAllowance-5*time.Second || !stored.ReadyDeadline.Equal(deadline) {
				t.Fatalf("invalid token mutated guest settlement: %+v, %v", stored, err)
			}
			if _, err := db.AllocateStreamCapacity(t.Context(), allocationRequest, deadline); !errors.Is(err, ErrStreamCapacity) {
				t.Fatalf("expired guest renewed allocation: %v", err)
			}
		})
	}
}

func TestIntegrationGuestAuthorityIngressPolicyStopsAtPublisherExpiry(t *testing.T) {
	db, now, request, relays := newPublishRunPrerequisites(t)
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	domainID, err := db.CreateGuestTrial(t.Context(), guest, "tunnels.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.EnsureGuestPrincipal(t.Context(), guest.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AllocateGuestDemoNumber(t.Context(), guest.ID, now); err != nil {
		t.Fatal(err)
	}
	url := createTestPublicURL(t, db, CreatePublicURLRequest{GuestID: guest.ID, TeamID: guest.TeamID, DomainID: domainID, MembershipID: guest.MembershipID,
		ActingIdentityID: guest.ID, IdempotencyKey: "guest-url", CanonicalHostname: "demo-1." + guest.NamespaceLabel + ".tunnels.example.test", Target: "http://127.0.0.1:3000",
		PublicURLScope: PublicURLScopeMember, Purpose: PublicURLPurposeDemo, AllowedIPPrefixes: []string{"192.0.2.7/32"}, DNSState: PublicURLDNSUnmanaged, PolicyRevision: 1, Ephemeral: true}, now)
	request.GuestID, request.PublicURLID, request.TeamID, request.MembershipID = guest.ID, url.ID, guest.TeamID, guest.MembershipID
	request.ActingIdentityID, request.CertificateIdentifiers = guest.ID, []string{url.CanonicalHostname}
	request.ExpectedMutationRevision = url.MutationRevision
	setup, err := db.CreatePublishRun(t.Context(), request, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	readyTestSession(t, publishRunFixture{db, now, request, setup, relays})
	q := controlstatedb.New(db.pool)
	runBefore, err := q.GetPublishRun(t.Context(), setup.PublishRunID)
	if err != nil {
		t.Fatal(err)
	}
	guestBefore, err := q.GetGuestTrialByID(t.Context(), guest.ID)
	if err != nil {
		t.Fatal(err)
	}
	storedURL, err := q.GetFeedbackPublicURL(t.Context(), url.ID)
	if err != nil {
		t.Fatal(err)
	}
	deadline := runBefore.PublisherExpiresAt.Time
	if runBefore.State != "ready" || runBefore.ClosedAt.Valid || !deadline.Equal(setup.ExpiresAt) ||
		guestBefore.ActivePublishRunID.String != setup.PublishRunID || guestBefore.UsedReadyNs != 0 ||
		!guestBefore.ReadyDeadline.Time.After(deadline) || !guestBefore.ExpiresAt.Time.After(guestBefore.ReadyDeadline.Time) {
		t.Fatal("fixture did not retain a ready guest with publisher expiry before its ready and credential bounds")
	}
	if err := db.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	ingress, err := db.RegisterIngress(t.Context(), IngressRegistration{IngressID: "guest-policy", IngressRunID: "guest-policy-run", ProtocolVersion: 1, ConnectionCapacity: 10, IngressPoolID: PrimaryIngressPoolID}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}
	ordinary := createTestPublicURL(t, db, oidcRouteRequest(t, db, now), now)
	ordinaryScope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: ordinary.ID}
	secret := sha256.Sum256([]byte("guest publisher expiry share"))
	share, err := db.CreateGuestShare(t.Context(), guest.ID, url.ID, "guest-share", "", sha256.Sum256(secret[:]), now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	source := ShareTokenSource{ShareID: share.ID, Secret: base64.RawURLEncoding.EncodeToString(secret[:])}
	allocationRequest := StreamCapacityRequest{Owner: ingress.IngressLeaseIdentity, Scope: scope, RunID: setup.PublishRunID, RunNumber: int64(setup.PublishRunNumber), RequestID: "guest-allocation", Capacity: 1}
	before := deadline.Add(-time.Second)
	allocation, err := db.AllocateStreamCapacity(t.Context(), allocationRequest, before)
	if err != nil || !allocation.ValidUntil.Equal(deadline) {
		t.Fatalf("pre-expiry allocation = %v, %v", allocation.ValidUntil, err)
	}
	issued, err := db.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, before)
	if err != nil || !issued.Permission.ExpiresAt.Equal(deadline) {
		t.Fatalf("pre-expiry token = %v, %v", issued.Permission.ExpiresAt, err)
	}
	policy, err := db.ReadIngressVisitorPolicy(t.Context(), ingress.IngressLeaseIdentity, scope, 0, before)
	if err != nil || !policy.Policy.Enabled || !policy.Policy.ValidUntil.Equal(deadline) {
		t.Fatalf("pre-expiry ingress policy: enabled=%v until=%v, %v", policy.Policy.Enabled, policy.Policy.ValidUntil, err)
	}
	assertGuestPolicyConsumer(t, scope, policy, true)
	for _, observation := range []struct {
		name  string
		after time.Duration
	}{{"equal", 0}, {"after", time.Second}} {
		t.Run(observation.name, func(t *testing.T) {
			at := deadline.Add(observation.after)
			var live, activeTeam bool
			var canonical time.Time
			if err := db.pool.QueryRow(t.Context(), `SELECT control.guest_share_live(id,$2),control.guest_serving_deadline(id,$2),
			    EXISTS(SELECT 1 FROM control.teams WHERE id=guest.team_id AND deleted_at IS NULL)
			    FROM control.guest_trials guest WHERE id=$1`, guest.ID, at).Scan(&live, &canonical, &activeTeam); err != nil {
				t.Fatal(err)
			}
			if !live || activeTeam || !canonical.Equal(deadline) || !guestBefore.ReadyDeadline.Time.After(at) || !guestBefore.ExpiresAt.Time.After(at) {
				t.Fatal("fixture did not reach the live guest's elapsed canonical publisher bound")
			}
			lease, err := lockCurrentIngressLeaseForPolicyTest(t, db, ingress.IngressLeaseIdentity, at)
			if err != nil || lease.IngressPoolID != storedURL.IngressPoolID || !lease.LeaseExpiresAt.Time.After(at) {
				t.Fatalf("exact ingress lease/pool is not current: %v", err)
			}
			t.Logf("observed=%s publisher=%s ready=%s credential=%s ingress=%s guest_live=%v", at, deadline, guestBefore.ReadyDeadline.Time, guestBefore.ExpiresAt.Time, lease.LeaseExpiresAt.Time, live)
			wire, err := db.ReadIngressVisitorPolicy(t.Context(), ingress.IngressLeaseIdentity, scope, 0, at)
			if err != nil {
				t.Fatal(err)
			}
			if wire.Policy.Enabled {
				t.Errorf("elapsed canonical guest deadline returned enabled policy: observed=%s deadline=%s valid_until=%s", at, canonical, wire.Policy.ValidUntil)
			}
			if !wire.Policy.ObservedAt.Equal(at) || !wire.Policy.ValidUntil.After(at) {
				t.Fatal("disabled observation cannot be applied by the existing consumer")
			}
			assertGuestPolicyConsumer(t, scope, wire, false)
			replay, err := db.ReadIngressVisitorPolicy(t.Context(), ingress.IngressLeaseIdentity, scope, wire.Policy.VisitorPolicyRevision, at)
			if err != nil || replay.Policy.Enabled || !replay.Policy.ValidUntil.Equal(wire.Policy.ValidUntil) || len(replay.Revisions) != 0 {
				t.Errorf("repeated policy read restored authority or changed its observation: %v", err)
			}
			if _, err := db.ReadPublisherVisitorPolicy(t.Context(), scope, setup.PublishRunID, int64(setup.PublishRunNumber), setup.PublishRunToken.String(), 0, nil, at); !errors.Is(err, ErrPublishRunCredential) {
				t.Fatalf("expired publisher policy credential accepted: %v", err)
			}
			if _, err := db.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, at); !errors.Is(err, ErrVisitorPermission) {
				t.Fatalf("expired publisher bound issued a visitor token: %v", err)
			}
			if _, err := db.AllocateStreamCapacity(t.Context(), allocationRequest, at); !errors.Is(err, ErrStreamCapacity) {
				t.Fatalf("expired publisher bound renewed allocation: %v", err)
			}
			ordinaryPolicy, err := db.ReadIngressVisitorPolicy(t.Context(), ingress.IngressLeaseIdentity, ordinaryScope, 0, at)
			if err != nil || !ordinaryPolicy.Policy.Enabled || !ordinaryPolicy.Policy.ValidUntil.Equal(at.Add(visitortoken.PolicyLifetime)) {
				t.Fatalf("ordinary non-guest policy changed: %v", err)
			}
			assertGuestPolicyConsumer(t, ordinaryScope, ordinaryPolicy, true)
			storedGuest, err := q.GetGuestTrialByID(t.Context(), guest.ID)
			if err != nil || !reflect.DeepEqual(storedGuest, guestBefore) {
				t.Fatal("policy/denial reads mutated the guest credential, ready budget, deadline or owner", err)
			}
			storedRun, err := q.GetPublishRun(t.Context(), setup.PublishRunID)
			if err != nil || !reflect.DeepEqual(storedRun, runBefore) {
				t.Fatal("policy/denial reads renewed or closed the publisher run", err)
			}
		})
	}
}

func lockCurrentIngressLeaseForPolicyTest(t *testing.T, db *Database, identity IngressLeaseIdentity, at time.Time) (controlstatedb.ControlIngressLease, error) {
	t.Helper()
	tx, err := db.pool.Begin(t.Context())
	if err != nil {
		return controlstatedb.ControlIngressLease{}, err
	}
	defer tx.Rollback(t.Context())
	return lockCurrentIngressLease(t.Context(), controlstatedb.New(tx), identity, at)
}

func assertGuestPolicyConsumer(t *testing.T, scope visitorscope.Scope, wire controlv1.VisitorPolicyUpdate, enabled bool) {
	t.Helper()
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	var body controlv1.VisitorPolicyUpdate
	if err := json.Unmarshal(encoded, &body); err != nil {
		t.Fatal(err)
	}
	if !body.Policy.ValidUntil.Equal(wire.Policy.ValidUntil) || !body.Policy.ObservedAt.Equal(wire.Policy.ObservedAt) {
		t.Fatal("encoded policy changed its observation bounds")
	}
	update, err := visitorlease.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := visitorlease.New(scope, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	request := lease.Begin()
	if err := lease.Apply(request, update); err != nil {
		t.Fatal("consumer rejected the encoded policy observation", err)
	}
	if _, got, _ := lease.Current(); got != enabled {
		t.Errorf("consumer enabled=%v, want %v", got, enabled)
	}
	if err := lease.Apply(request, update); !errors.Is(err, visitorlease.ErrUpdate) {
		t.Fatal("consumer accepted a replayed observation", err)
	}
}
