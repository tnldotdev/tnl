package public

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationServiceNamespaceHintUsesOnlyCurrentActorAuthority(t *testing.T) {
	f := newRestoredServiceHTTP(t)
	now := time.Now()
	domains, err := f.database.ListTeamDomains(t.Context(), f.actor, f.team)
	if err != nil || len(domains) == 0 {
		t.Fatal("namespace fixture has no ready domain", err)
	}
	members, err := f.database.ListTeamMemberships(t.Context(), f.actor, f.team)
	if err != nil || len(members) != 1 {
		t.Fatal("namespace fixture has no exact owner", err)
	}
	domain := domains[0]
	ownerNamespace := members[0].MemberSlug + "." + members[0].ManagedLabel + "." + domain.CanonicalDomain
	ownerHost := "private." + ownerNamespace
	saved, err := f.database.CreateServiceAt(t.Context(), f.team, f.actor, "private-owner", "private-owner",
		controlstate.ServicePlacement{DomainID: domain.ID, Hostname: ownerHost}, now,
		controlstate.ServiceMetadata{Protocol: "http"}, &controlstate.ProjectServiceConfiguration{Protocol: "http", Target: "app"})
	if err != nil {
		t.Fatal("owner could not create its exact hostname", err)
	}
	recipient, err := f.database.AuthenticateAccessToken(t.Context(), credentials.AccessToken(f.foreign), now)
	if err != nil {
		t.Fatal(err)
	}
	invite, err := f.database.CreateTeamInvitation(t.Context(), controlstate.CreateInvitationRequest{
		IdentityID: f.actor, TeamID: f.team, MemberSlug: "review-member", InitialRole: controlstate.TeamRoleMember,
		IdempotencyKey: "namespace-member", ExpiresAt: now.Add(time.Hour), RetrySecret: bytes.Repeat([]byte{7}, 32),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.AcceptInvitation(t.Context(), recipient.IdentityID, credentials.InvitationToken(invite.Secret), now); err != nil {
		t.Fatal(err)
	}
	members, err = f.database.ListTeamMemberships(t.Context(), f.actor, f.team)
	if err != nil {
		t.Fatal(err)
	}
	var member controlstate.Membership
	for _, candidate := range members {
		if candidate.IdentityID == recipient.IdentityID {
			member = candidate
		}
	}
	if member.ID == "" {
		t.Fatal("invitation did not create current membership")
	}
	namespace := member.MemberSlug + "." + member.ManagedLabel + "." + domain.CanonicalDomain
	call := func(token, hostname, key string, hint bool) string {
		t.Helper()
		body := fmt.Sprintf(`{"team_id":%q,"name":%q,"reserve":true,"placement":{"domain_id":%q,"hostname":%q},"configuration":{"protocol":"http","target":"app"}}`,
			f.team, key, domain.ID, hostname)
		status, wire, _ := f.call(token, http.MethodPost, "/v1/services", key, []byte(body))
		var problem controlv1.Problem
		if status != 404 || json.Unmarshal(wire, &problem) != nil || problem.Code != controlv1.NotFound ||
			strings.Contains(problem.Title, namespace) != hint {
			t.Fatal("namespace error did not follow current actor authority", status, string(wire))
		}
		var allowed any
		if problem.Details != nil {
			allowed = (*problem.Details)["allowed_namespace"]
		}
		if hint && allowed != namespace || !hint && allowed != nil {
			t.Fatal("structured namespace hint did not follow current actor authority", status, string(wire))
		}
		for _, private := range []string{ownerNamespace, saved.ID, f.actor, member.ID} {
			if strings.Contains(string(wire), private) {
				t.Fatal("namespace denial disclosed another owner or protected identity")
			}
		}
		return problem.Title
	}
	// existence of a foreign service must not change the diagnostic. only the
	// caller's already-authorized namespace is useful here.
	existing := call(f.foreign, ownerHost, "deny-existing", true)
	missing := call(f.foreign, "absent."+ownerNamespace, "deny-missing", true)
	if existing != missing {
		t.Fatal("namespace denial revealed whether a foreign hostname exists")
	}
	if err := f.database.RemoveMembership(t.Context(), f.actor, f.team, member.ID, now); err != nil {
		t.Fatal(err)
	}
	call(f.foreign, ownerHost, "deny-removed", false)
	status, wire, _ := f.call(f.foreign, http.MethodGet, "/v1/services/"+saved.ID, "", nil)
	if status != 404 || strings.Contains(string(wire), namespace) || strings.Contains(string(wire), ownerNamespace) {
		t.Fatal("protected read disclosed a namespace after removal", status, string(wire))
	}
}
