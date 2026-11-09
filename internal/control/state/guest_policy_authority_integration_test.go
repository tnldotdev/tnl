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
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationGuestAuthorityBoundsPreparationPolicyAndPermissions(t *testing.T) {
	for _, bound := range []string{"ready", "credential", "publisher"} {
		t.Run(bound, func(t *testing.T) {
			db, now, request, relays := newPublishRunPrerequisites(t)
			guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
			if err != nil {
				t.Fatal(err)
			}
			domain, err := db.CreateGuestTrial(t.Context(), guest, "routes.example.test", now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.EnsureGuestPrincipal(t.Context(), guest.ID, now); err != nil {
				t.Fatal(err)
			}
			if _, err := db.AllocateGuestDemoNumber(t.Context(), guest.ID, now); err != nil {
				t.Fatal(err)
			}
			url := createTestPublicURL(t, db, CreatePublicURLRequest{GuestID: guest.ID, TeamID: guest.TeamID, DomainID: domain, MembershipID: guest.MembershipID,
				ActingIdentityID: guest.ID, IdempotencyKey: "guest-url", CanonicalHostname: "demo-1." + guest.NamespaceLabel + ".routes.example.test", Target: "http://127.0.0.1:3000",
				PublicURLScope: PublicURLScopeMember, Purpose: PublicURLPurposeDemo, AllowedIPPrefixes: []string{"192.0.2.7/32"}, DNSState: PublicURLDNSUnmanaged, PolicyRevision: 1, Ephemeral: true}, now)
			request.GuestID, request.PublicURLID, request.TeamID, request.MembershipID = guest.ID, url.ID, guest.TeamID, guest.MembershipID
			request.ActingIdentityID, request.CertificateIdentifiers, request.ExpectedMutationRevision = guest.ID, []string{url.CanonicalHostname}, url.MutationRevision
			remaining := 6 * time.Second
			deadline := now.Add(remaining)
			lease := time.Hour
			if bound == "credential" {
				deadline = now.Add(5 * time.Second)
				if _, err := db.pool.Exec(t.Context(), `UPDATE control.guest_trials SET expires_at=$2 WHERE id=$1`, guest.ID, deadline); err != nil {
					t.Fatal(err)
				}
			} else if bound == "publisher" {
				lease, remaining = 5*time.Second, GuestReadyAllowance
				deadline = now.Add(lease)
			}
			if _, err := db.pool.Exec(t.Context(), `UPDATE control.guest_trials SET used_ready_ns=$2 WHERE id=$1`, guest.ID, int64(GuestReadyAllowance-remaining)); err != nil {
				t.Fatal(err)
			}
			setup, err := db.CreatePublishRun(t.Context(), request, now, lease, time.Minute)
			if err != nil || !setup.ExpiresAt.Equal(deadline) {
				t.Fatalf("preparation publisher horizon = %v, %v", setup.ExpiresAt, err)
			}
			f := publishRunFixture{db, now, request, setup, relays}
			if err := db.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
				t.Fatal(err)
			}
			owner := registerServingIngress(t, f, "guest-policy", now)
			scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}
			var token visitortoken.Token
			checkPolicy := func(at time.Time, serving bool) {
				t.Helper()
				publisher, err := db.ReadPublisherVisitorPolicy(t.Context(), scope, setup.PublishRunID, int64(setup.PublishRunNumber), setup.PublishRunToken.String(), 0, at)
				if err != nil || !publisher.Policy.ValidUntil.Equal(deadline) || publisher.Policy.ConnectionDeadline == nil || !publisher.Policy.ConnectionDeadline.Equal(deadline) {
					t.Fatalf("publisher policy horizon = %+v, %v", publisher.Policy, err)
				}
				decoded, err := visitorlease.Decode(publisher)
				if err != nil {
					t.Fatal(err)
				}
				verified, err := visitortoken.VerifyBearer(token, decoded.View, at)
				if serving {
					if err != nil || !verified.Facts().ExpiresAt.Equal(deadline) {
						t.Fatal("opaque guest share lost its fixed serving horizon", err)
					}
				} else if !errors.Is(err, visitortoken.ErrToken) || len(publisher.Policy.ShareVerifiers) != 0 {
					t.Fatal("preparation granted uncharged opaque visitor permission", err)
				}
				ingress, err := db.ReadIngressVisitorPolicy(t.Context(), owner, scope, setup.PublishRunID, int64(setup.PublishRunNumber), int64(request.PolicyRevision), 0, at)
				if err != nil || !ingress.Policy.ValidUntil.Equal(deadline) {
					t.Fatalf("ingress policy horizon = %v, %v", ingress.Policy.ValidUntil, err)
				}
				delegated, err := tunnelv1.ReadVisitorSourceAuthority(*ingress.VisitorSourceAuthority)
				if err != nil || delegated.ValidUntil != deadline.Unix() {
					t.Fatalf("ingress source authority = %+v, %v", delegated, err)
				}
				wire, err := json.Marshal(ingress)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(wire, &ingress); err != nil {
					t.Fatal(err)
				}
				update, err := visitorlease.Decode(ingress)
				if err != nil || !update.BoundConnections {
					t.Fatalf("wire lost connection authority: %v", err)
				}
			}
			secret := sha256.Sum256([]byte("guest share secret"))
			share, err := db.CreateGuestShare(t.Context(), guest.ID, url.ID, "guest-share", "", sha256.Sum256(secret[:]), now.Add(time.Hour), now)
			if err != nil {
				t.Fatal(err)
			}
			source := ShareTokenSource{ShareID: share.ID, Secret: base64.RawURLEncoding.EncodeToString(secret[:])}
			token, err = visitortoken.ShareToken(share.ID, secret[:])
			if err != nil {
				t.Fatal(err)
			}
			observations := 1
			if bound == "ready" {
				observations = 3
			}
			for observation := range observations {
				if observation > 0 {
					// preparation can outlast the remaining allowance, but must never
					// turn those renewable observations into uncharged permission.
					now = now.Add(4 * time.Second)
					deadline = now.Add(remaining)
					renewed, err := db.HeartbeatPublishRun(t.Context(), f.authentication(), now, time.Hour, time.Minute)
					if err != nil || !renewed.ExpiresAt.Equal(deadline) {
						t.Fatalf("preparation renewal = %v, %v", renewed.ExpiresAt, err)
					}
				}
				checkPolicy(now, false)
				if _, err := db.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, now); !errors.Is(err, ErrVisitorPermission) {
					t.Fatalf("starting guest issued visitor permission: %v", err)
				}
				before, err := db.GuestTrialByAccessToken(t.Context(), guest.Token)
				if err != nil || before.UsedReady != GuestReadyAllowance-remaining || !before.ReadyDeadline.IsZero() || !before.ServingUntil.IsZero() {
					t.Fatalf("preparation started charging: %+v, %v", before, err)
				}
			}
			f.now = now
			readyTestSession(t, f)
			for _, elapsed := range []time.Duration{time.Second, 3 * time.Second} {
				at := now.Add(elapsed)
				if bound != "publisher" {
					renewed, err := db.HeartbeatPublishRun(t.Context(), f.authentication(), at, time.Hour, time.Minute)
					if err != nil || !renewed.ExpiresAt.Equal(deadline) {
						t.Fatalf("heartbeat slid guest authority: %v, %v", renewed.ExpiresAt, err)
					}
				}
				checkPolicy(at, true)
				issued, err := db.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, at)
				if err != nil || !issued.Permission.ExpiresAt.Equal(deadline) {
					t.Fatalf("visitor permission = %v, %v", issued.Permission.ExpiresAt, err)
				}
			}
			q := controlstatedb.New(db.pool)
			stored, err := q.GetGuestTrialByID(t.Context(), guest.ID)
			if err != nil {
				t.Fatal(err)
			}
			for _, at := range []time.Time{deadline, deadline.Add(time.Second)} {
				if _, err := db.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, at); !errors.Is(err, ErrVisitorPermission) {
					t.Fatalf("expired guest issued permission: %v", err)
				}
				if _, err := db.ReadIngressVisitorPolicy(t.Context(), owner, scope, setup.PublishRunID, int64(setup.PublishRunNumber), int64(request.PolicyRevision), 0, at); !errors.Is(err, ErrVisitorPolicy) {
					t.Fatalf("expired run issued ingress authority: %v", err)
				}
				if _, err := db.ReadPublisherVisitorPolicy(t.Context(), scope, setup.PublishRunID, int64(setup.PublishRunNumber), setup.PublishRunToken.String(), 0, at); !errors.Is(err, ErrPublishRunCredential) {
					t.Fatalf("expired run issued publisher policy: %v", err)
				}
			}
			after, err := q.GetGuestTrialByID(t.Context(), guest.ID)
			if err != nil || !reflect.DeepEqual(after, stored) {
				t.Fatal("read-only denials mutated guest authority", err)
			}
			if _, err := db.HeartbeatPublishRun(t.Context(), f.authentication(), deadline, time.Hour, time.Minute); !errors.Is(err, ErrPublishRunStale) {
				t.Fatalf("expired publisher lease revived: %v", err)
			}
			if err := db.ClosePublishRun(t.Context(), setup.PublishRunID, setup.PublishRunToken, deadline.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			if _, err := db.IssueVisitorToken(t.Context(), testVisitorIssuer, scope, source, deadline.Add(time.Hour)); !errors.Is(err, ErrVisitorPermission) {
				t.Fatalf("closed run restored visitor permission: %v", err)
			}
			final, err := db.GuestTrialByAccessToken(t.Context(), guest.Token)
			if err != nil || final.UsedReady != GuestReadyAllowance-remaining+deadline.Sub(now) {
				t.Fatalf("settled time exceeds issued authority: %+v, %v", final, err)
			}
		})
	}
}

func TestIntegrationGuestAuthorityOrdinaryPolicyUnchanged(t *testing.T) {
	f := newPublishRunFixture(t)
	if err := f.database.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, f.now); err != nil {
		t.Fatal(err)
	}
	url := createTestPublicURL(t, f.database, oidcRouteRequest(t, f.database, f.now), f.now)
	policy := policyObservation(t, f.database, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}, 0)
	if !policy.Policy.Enabled || policy.Policy.ConnectionDeadline != nil || !policy.Policy.ValidUntil.Equal(policy.Policy.ObservedAt.Add(visitortoken.PolicyLifetime)) {
		t.Fatalf("ordinary policy changed: %+v", policy.Policy)
	}
	renewed, err := f.database.HeartbeatPublishRun(t.Context(), f.authentication(), f.now.Add(time.Second), time.Hour, time.Minute)
	if err != nil || !renewed.ExpiresAt.Equal(f.now.Add(time.Hour+time.Second)) {
		t.Fatalf("ordinary publisher lease changed: %v, %v", renewed.ExpiresAt, err)
	}
}
