package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationPublisherIdentityReturnsStoredGrantExpiry(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "publisher_grant_receipt")
	r := oidcRouteRequest(t, d, now)
	service := createTestPublicURL(t, d, r, now)
	member, err := controlstatedb.New(d.pool).GetActivePublishRunMembership(t.Context(), controlstatedb.GetActivePublishRunMembershipParams{
		TeamID: r.TeamID, IdentityID: r.ActingIdentityID,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"installed", "automation", "run"} {
		t.Run(kind, func(t *testing.T) {
			enrollment, err := d.IssuePublisherEnrollment(t.Context(), CreatePublisherEnrollmentRequest{
				Scope: PublisherScope{TeamID: r.TeamID, Kind: "saved_public_url", PublicURLID: service.ID},
				Name:  "receipt", Kind: kind, EditorID: r.ActingIdentityID, EditorMembershipID: member.ID,
				PolicyRevision: uint64(member.PolicyRevision), Now: now,
			})
			if err != nil {
				t.Fatal(err)
			}
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
			if err != nil {
				t.Fatal(err)
			}
			stored, err := controlstatedb.New(d.pool).GetPublisherGrant(t.Context(), controlstatedb.GetPublisherGrantParams{
				ID: publisher.GrantID, PublisherIdentityID: publisher.ID,
			})
			if err != nil || !reflect.DeepEqual(publisher.ExpiresAt, optionalTime(stored.ExpiresAt)) ||
				(kind == "installed") != (publisher.ExpiresAt == nil) {
				t.Fatalf("receipt did not return exact optional grant expiry: %+v, %v", publisher, err)
			}
			recovered, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now.Add(time.Second))
			if err != nil || !reflect.DeepEqual(publisher, recovered) {
				t.Fatalf("redemption recovery changed grant expiry: %+v, %v", recovered, err)
			}
			access := publisherAccess(t, d, publisher, private, "", now)
			authenticated, err := d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now)
			if err != nil || !reflect.DeepEqual(authenticated, publisher) ||
				!reflect.DeepEqual(access.ExpiresAt, publisher.ExpiresAt) || !access.Until.Equal(now.Add(PublisherAccessLifetime)) {
				t.Fatalf("authentication confused grant and token expiry: %+v, %v", authenticated, err)
			}
		})
	}
}
