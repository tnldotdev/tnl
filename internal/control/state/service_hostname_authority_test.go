package state

import (
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestServiceHostnameDescendantsRetainMembershipOwnership(t *testing.T) {
	for _, kind := range []string{"managed", "custom"} {
		t.Run(kind, func(t *testing.T) {
			context := controlstatedb.GetPublicURLCreationContextRow{
				DomainState: "ready", DomainKind: kind, CanonicalDomain: "example.test",
				ActorMembershipID: "membership_actor", ActorRole: "owner",
				ActorMemberSlug: "actor", ActorManagedLabel: "actor-unique",
			}
			label := context.ActorMemberSlug
			if kind == "managed" {
				label = context.ActorManagedLabel
			} else {
				context.DomainTeamID = text("team_actor")
			}
			check := func(hostname string) error {
				return authorizeServiceHostname(context, nil, "team_actor", "membership_actor", hostname, "member", "")
			}
			for _, hostname := range []string{"review." + label + ".example.test", "api.shop." + label + ".example.test"} {
				if err := check(hostname); err != nil {
					t.Fatalf("own descendant %q rejected: %v", hostname, err)
				}
			}
			if err := check(label + ".example.test"); !errors.Is(err, ErrServiceAccess) {
				t.Fatalf("member namespace apex was published: %v", err)
			}
			for _, hostname := range []string{"api.shop.other.example.test", "api.shop.not-" + label + ".example.test", "api.example.test"} {
				if err := check(hostname); !errors.Is(err, ErrServiceAccess) {
					t.Fatalf("foreign namespace %q authorized: %v", hostname, err)
				}
			}
			if kind == "custom" {
				labels := []controlstatedb.ListTeamNamespaceLabelsRow{{MemberSlug: "other"}}
				if err := authorizeServiceHostname(context, labels, "team_actor", "", "api.shop.other.example.test", "shared", ""); !errors.Is(err, ErrServiceAccess) {
					t.Fatal("shared service claimed another member's nested namespace")
				}
			}
		})
	}
}
