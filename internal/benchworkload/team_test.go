package benchworkload

import (
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestPublisherMembershipSelectsOnlyRequestedTeam(t *testing.T) {
	identity := authorityv1.IdentityContext{PersonalTeamId: "team_personal", Memberships: []authorityv1.Membership{
		{Id: "membership_personal", TeamId: "team_personal", ManagedLabel: "personal"},
		{Id: "membership_test", TeamId: "team_test", ManagedLabel: "test"},
	}}
	member, err := publisherMembership(identity, "team_test")
	if err != nil || member.Id != "membership_test" {
		t.Fatalf("selected membership = %+v, %v", member, err)
	}
	for _, team := range []string{"", "team_missing"} {
		if _, err := publisherMembership(identity, team); err == nil {
			t.Fatalf("accepted unselected team %q", team)
		}
	}
	identity.Memberships[1].ManagedLabel = ""
	if _, err := publisherMembership(identity, "team_test"); err == nil || !strings.Contains(err.Error(), "no membership") {
		t.Fatalf("accepted invalid membership: %v", err)
	}
}
