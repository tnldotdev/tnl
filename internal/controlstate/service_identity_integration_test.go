package controlstate

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
)

func TestIntegrationWebsiteAndOIDCShareIdentityAndMemberships(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "website_identity")
	identity := OIDCIdentity{Issuer: "https://account.example", Subject: "sam", DisplayName: "Sam", NormalizedEmail: "sam@example.com", EmailVerified: true}
	web, err := database.EnsureServiceIdentity(t.Context(), "routes.example.test", identity, now)
	if err != nil {
		t.Fatal(err)
	}
	identity.AssertionDigest, identity.AssertionExpiry = sha256.Sum256([]byte("assertion")), now.Add(time.Hour)
	cli, err := database.CreateOIDCControlSession(t.Context(), "routes.example.test", identity, time.Hour, 24*time.Hour, now)
	if err != nil || cli.Identity.Identity.ID != web.Identity.ID || cli.Identity.PersonalTeamID != web.PersonalTeamID {
		t.Fatalf("CLI identity=%+v error=%v", cli.Identity, err)
	}
	owner, err := database.CreateBuiltinControlSession(t.Context(), "routes.example.test", 1, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	team, err := database.CreateTeam(t.Context(), CreateTeamRequest{IdentityID: owner.Identity.Identity.ID, IdempotencyKey: "studio", DisplayName: "studio", MemberSlug: "owner"}, now)
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := database.CreateTeamInvitation(t.Context(), CreateInvitationRequest{IdentityID: owner.Identity.Identity.ID, TeamID: team.ID, IdempotencyKey: "invite-sam", MemberSlug: "sam", InitialRole: TeamRoleMember, EmailRestriction: identity.NormalizedEmail, ExpiresAt: now.Add(time.Hour), RetrySecret: make([]byte, 32)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if preview, err := database.PreviewInvitation(t.Context(), web.Identity.ID, invitation.Secret, now); err != nil || preview.TeamDisplayName != "studio" {
		t.Fatalf("preview=%+v error=%v", preview, err)
	}
	identity.EmailVerified, identity.NormalizedEmail = false, ""
	if _, err := database.EnsureServiceIdentity(t.Context(), "routes.example.test", identity, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.PreviewInvitation(t.Context(), web.Identity.ID, invitation.Secret, now); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatalf("unverified email preview=%v", err)
	}
	identity.EmailVerified, identity.NormalizedEmail = true, "sam@example.com"
	if _, err := database.EnsureServiceIdentity(t.Context(), "routes.example.test", identity, now); err != nil {
		t.Fatal(err)
	}
	membership, err := database.AcceptInvitation(t.Context(), web.Identity.ID, credentials.InvitationToken(invitation.Secret), now)
	if err != nil {
		t.Fatal(err)
	}
	web, err = database.EnsureServiceIdentity(t.Context(), "routes.example.test", identity, now)
	if err != nil || len(web.Memberships) != 2 {
		t.Fatalf("website memberships=%+v error=%v", web.Memberships, err)
	}
	if err := database.RemoveMembership(t.Context(), owner.Identity.Identity.ID, team.ID, membership.ID, now); err != nil {
		t.Fatal(err)
	}
	web, err = database.EnsureServiceIdentity(t.Context(), "routes.example.test", identity, now)
	if err != nil || len(web.Memberships) != 1 {
		t.Fatalf("removed membership still visible: %+v, %v", web, err)
	}
}
