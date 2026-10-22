package state

import (
	"testing"
	"time"
)

func TestIntegrationOIDCSeedsRemainRevoked(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "oidc_seeds")
	seeds := HumanAuthenticationSeeds{Issuer: "https://identity.example.test", Administrators: []string{"operator"}, TeamOwners: map[string]string{"studio": "owner"}, DefaultTeam: "studio", DefaultTeamMembers: []string{"member"}}
	if err := d.SeedHumanAuthentication(t.Context(), "tunnels.example.test", seeds, now); err != nil {
		t.Fatal(err)
	}
	resolve := func(subject string) IdentityContext {
		t.Helper()
		identity, err := d.EnsureServiceIdentity(t.Context(), "tunnels.example.test", OIDCIdentity{Issuer: seeds.Issuer, Subject: subject, DisplayName: subject}, now)
		if err != nil {
			t.Fatal(err)
		}
		return identity
	}
	admin, owner, member := resolve("operator"), resolve("owner"), resolve("member")
	if !admin.Identity.Administrator || owner.Identity.Administrator || member.Identity.Administrator {
		t.Fatal("administrator seeds were not exact identities")
	}
	var team string
	var memberID, ownerID string
	for _, m := range member.Memberships {
		if m.TeamKind == TeamKindOrganization {
			team, memberID = m.TeamID, m.ID
		}
	}
	for _, m := range owner.Memberships {
		if m.TeamID == team {
			ownerID = m.ID
		}
	}
	if team == "" || member.DefaultTeamID != team || memberID == "" || ownerID == "" {
		t.Fatalf("initial team was not selected: %#v", member)
	}
	otherOwner := addAuthorityMember(t, d, now, owner.Identity.ID, team, "second-owner", TeamRoleOwner)
	if otherOwner.Role != TeamRoleOwner {
		t.Fatal("second owner fixture failed")
	}
	if _, err := d.SetMembershipRole(t.Context(), owner.Identity.ID, team, ownerID, TeamRoleMember, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveMembership(t.Context(), otherOwner.IdentityID, team, memberID, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.identities SET administrator=false WHERE id=$1`, admin.Identity.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.SeedHumanAuthentication(t.Context(), "tunnels.example.test", seeds, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if resolve("operator").Identity.Administrator {
		t.Fatal("restart restored revoked administrator privilege")
	}
	member = resolve("member")
	if member.DefaultTeamID != member.PersonalTeamID {
		t.Fatal("removed default team was still selected")
	}
	for _, m := range member.Memberships {
		if m.TeamID == team {
			t.Fatal("restart restored removed default membership")
		}
	}
	owner = resolve("owner")
	for _, m := range owner.Memberships {
		if m.ID == ownerID && m.Role != TeamRoleMember {
			t.Fatal("restart restored revoked organization ownership")
		}
	}
}
