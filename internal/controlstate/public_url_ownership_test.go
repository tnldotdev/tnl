package controlstate

import (
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

func TestMemberURLDescendantsRetainMembershipOwnership(t *testing.T) {
	for _, kind := range []string{"managed", "claimed"} {
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
			request := CreatePublicURLRequest{TeamID: "team_actor", MembershipID: "membership_actor", PublicURLScope: PublicURLScopeMember}
			for _, hostname := range []string{label + ".example.test", "review." + label + ".example.test", "api.shop." + label + ".example.test"} {
				request.CanonicalHostname = hostname
				if err := authorizeRouteCreation(request, context, nil); err != nil {
					t.Fatalf("own descendant %q rejected: %v", hostname, err)
				}
			}
			for _, hostname := range []string{"api.shop.other.example.test", "api.shop.not-" + label + ".example.test", "api.example.test"} {
				request.CanonicalHostname = hostname
				if err := authorizeRouteCreation(request, context, nil); !errors.Is(err, ErrPublicURLAccess) {
					t.Fatalf("foreign namespace %q authorized: %v", hostname, err)
				}
			}
			if kind == "claimed" {
				request.MembershipID, request.PublicURLScope, request.CanonicalHostname = "", PublicURLScopeShared, "api.shop.other.example.test"
				labels := []controlstatedb.ListTeamNamespaceLabelsRow{{MemberSlug: "other"}}
				if err := authorizeRouteCreation(request, context, labels); !errors.Is(err, ErrPublicURLAccess) {
					t.Fatal("shared URL claimed another member's nested namespace")
				}
			}
		})
	}
}
