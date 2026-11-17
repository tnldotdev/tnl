package state

import (
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationServiceRestoredPersonalDirectHostnameRejectsMemberScope(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "restored_personal_scope")
	session := newOIDCSession(t, d, now)
	actor, team := session.Identity.Identity.ID, session.Identity.PersonalTeamID
	d.managedURLMode = naming.ManagedURLModeSimple
	// platform administrator status must not turn a direct personal name into
	// an individual member namespace.
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.identities SET administrator=true WHERE id=$1`, actor); err != nil {
		t.Fatal(err)
	}
	domains, err := d.ListTeamDomains(t.Context(), actor, team)
	if err != nil || len(domains) != 1 {
		t.Fatal("personal team lacks its managed domain", err)
	}
	custom := deploymentCustomDomain(t, d, ApplyProjectConfigurationRequest{TeamID: team, ActorID: actor}, now)
	for _, domain := range []Domain{domains[0], custom} {
		t.Run(string(domain.Kind), func(t *testing.T) {
			tx, err := d.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, tx)
			facts, err := serviceHostnameAuthority(t.Context(), tx, team, actor, domain.ID, now)
			if err != nil {
				t.Fatal(err)
			}
			labels, err := controlstatedb.New(tx).ListTeamNamespaceLabels(t.Context(), team)
			if err != nil {
				t.Fatal(err)
			}
			if facts.TeamKind != "personal" {
				t.Fatal("fixture did not select a personal team")
			}
			hostname := "app." + facts.CanonicalDomain
			if err := authorizeServiceHostname(facts, labels, team, facts.ActorMembershipID, hostname, "member", d.managedURLMode); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("member scope claimed a direct personal hostname", err)
			}
			err = authorizeServiceHostname(facts, labels, team, "", hostname, "shared", d.managedURLMode)
			if domain.Kind == DomainKindCustom {
				if err != nil {
					t.Fatal("shared personal scope rejected its own custom domain", err)
				}
			} else {
				// managed shared names are now team-bound, not server-wide.
				if !errors.Is(err, ErrServiceAccess) {
					t.Fatal("administrator claimed the server-wide managed suffix", err)
				}
				hostname = "app." + facts.TeamDisplayName + "." + facts.CanonicalDomain
				for _, scope := range []string{"member", "shared"} {
					membership := ""
					if scope == "member" {
						membership = facts.ActorMembershipID
					}
					if err := authorizeServiceHostname(facts, labels, team, membership, hostname, scope, d.managedURLMode); err != nil {
						t.Fatal("team-bound personal managed hostname was denied", scope, err)
					}
				}
			}
		})
	}
}
