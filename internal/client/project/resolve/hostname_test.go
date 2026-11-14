package resolve

import (
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func TestProjectPublishHostnameUsesNamespace(t *testing.T) {
	current := team.NewContext(
		authorityv1.Team{Id: "team_1", DefaultDomainId: "domain_1", PolicyRevision: 4},
		authorityv1.Membership{Id: "membership_1", TeamId: "team_1", Role: authorityv1.TeamRoleMember, MemberSlug: "chase", ManagedLabel: "chase-abc"},
		[]authorityv1.Domain{{Id: "domain_1", Kind: authorityv1.Managed, CanonicalDomain: "tnl.dev", State: authorityv1.DomainStateReady}}, "",
	)
	hostname, domain, err := PublishHostname("", "api", "", current)
	if err != nil {
		t.Fatal(err)
	}
	if hostname != "api.chase-abc.tnl.dev" || domain.Id != "domain_1" {
		t.Fatalf("resolution = %q, %#v", hostname, domain)
	}
	if _, _, err := PublishHostname("shared.tnl.dev", "", "", current); err == nil {
		t.Fatal("member was allowed to create a shared route")
	}
	generated, _, err := PublishHostname("", "", "", current)
	if err != nil {
		t.Fatal(err)
	}
	label, found := strings.CutSuffix(generated, ".chase-abc.tnl.dev")
	if !found || strings.Count(label, "-") != 1 {
		t.Fatalf("generated service hostname = %q", generated)
	}
}

func TestProjectPublishHostnameScopeMatrix(t *testing.T) {
	for _, test := range []struct {
		name, kind, host string
	}{
		{"managed", "managed", ""},
		{"custom", "custom", ""},
		{"shared", "custom", "shared.routes.example.test"},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := team.NewContext(
				authorityv1.Team{Id: "team_1", DefaultDomainId: "domain_1", PolicyRevision: 1},
				authorityv1.Membership{Id: "membership_1", TeamId: "team_1", Role: authorityv1.TeamRoleOwner,
					MemberSlug: "member", ManagedLabel: "member-unique"},
				[]authorityv1.Domain{{Id: "domain_1", Kind: authorityv1.DomainKind(test.kind),
					CanonicalDomain: "routes.example.test", State: authorityv1.DomainStateReady}}, "",
			)
			namespace := "member.routes.example.test"
			if test.kind == "managed" {
				namespace = "member-unique.routes.example.test"
			}
			name, wantHost := "api", "api."+namespace
			if test.host != "" {
				name, wantHost = "", test.host
			}
			for _, role := range []authorityv1.TeamRole{authorityv1.TeamRoleOwner, authorityv1.TeamRoleMember} {
				membership := current.Membership()
				membership.Role = role
				selected := team.NewContext(current.Team(), membership, current.Domains(), "")
				hostname, domain, err := PublishHostname(test.host, name, "", selected)
				if test.host != "" && role == authorityv1.TeamRoleMember {
					if err == nil {
						t.Fatal("member was allowed to claim a shared hostname")
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if hostname != wantHost || domain.Id != "domain_1" {
					t.Fatalf("resolution = %q, %q; want %q", hostname, domain.Id, wantHost)
				}
			}
		})
	}
}

func TestProjectManagedAndCustomDefaultURLShapes(t *testing.T) {
	for _, test := range []struct {
		name, mode, teamKind, domainKind, teamName, domain, want, scope string
	}{
		{"personal_managed", "simple", "personal", "managed", "chase", "routes.example.test", "app.chase.routes.example.test", "member"},
		{"organization_managed", "simple", "organization", "managed", "studio", "routes.example.test", "app.chase.studio.routes.example.test", "member"},
		{"personal_custom", "simple", "personal", "custom", "chase", "dev.example.test", "app.dev.example.test", "shared"},
		{"organization_custom", "simple", "organization", "custom", "studio", "studio.example.test", "app.chase.studio.example.test", "member"},
		{"hosted_generated", "generated", "organization", "managed", "studio", "tnl.dev", "app.ecstatic-penguin.tnl.dev", "member"},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := team.NewContext(
				authorityv1.Team{Id: "team", Kind: authorityv1.TeamKind(test.teamKind), DisplayName: test.teamName, DefaultDomainId: "domain"},
				authorityv1.Membership{Id: "member", TeamId: "team", Role: authorityv1.TeamRoleOwner,
					MemberSlug: "chase", ManagedLabel: "ecstatic-penguin"},
				[]authorityv1.Domain{{Id: "domain", Kind: authorityv1.DomainKind(test.domainKind),
					CanonicalDomain: test.domain, State: authorityv1.DomainStateReady}},
				naming.ManagedURLMode(test.mode),
			)
			hostname, _, err := PublishHostname("", "app", "", current)
			if err != nil || hostname != test.want {
				t.Fatalf("hostname=%q error=%v; want %q", hostname, err, test.want)
			}
			if test.scope == "member" {
				namespace, _ := current.Namespace(current.Domains()[0])
				if _, _, err := PublishHostname(namespace, "", "", current); err == nil {
					t.Fatal("member namespace apex was accepted")
				}
			}
		})
	}
}

func TestProjectExplicitHostnameUsesReadyDomainWhenDefaultIsPending(t *testing.T) {
	current := team.NewContext(
		authorityv1.Team{Id: "team_1", DefaultDomainId: "domain_pending"},
		authorityv1.Membership{Id: "membership_1", TeamId: "team_1",
			Role: authorityv1.TeamRoleOwner, MemberSlug: "member", ManagedLabel: "managed-member"},
		[]authorityv1.Domain{
			{Id: "domain_pending", CanonicalDomain: "pending.example.test", State: authorityv1.DomainStatePending},
			{Id: "domain_ready", CanonicalDomain: "ready.example.test", Kind: authorityv1.Custom, State: authorityv1.DomainStateReady},
		}, "",
	)
	hostname, domain, err := PublishHostname("api.member.ready.example.test", "", "", current)
	if err != nil || hostname != "api.member.ready.example.test" || domain.Id != "domain_ready" {
		t.Fatalf("explicit hostname = %q, %+v, %v", hostname, domain, err)
	}
	if _, _, err := PublishHostname("", "api", "", current); err == nil {
		t.Fatal("default-domain name was accepted while its domain is pending")
	} else if reason, _, ok := failure.Describe(err); !ok || reason != failure.DomainNotReady {
		t.Fatalf("pending domain reason = %q, %v", reason, err)
	}
	hostname, domain, err = PublishHostname("", "api", "ready.example.test", current)
	if err != nil || hostname != "api.member.ready.example.test" || domain.Id != "domain_ready" {
		t.Fatalf("project domain = %q, %+v, %v", hostname, domain, err)
	}
	for _, selected := range []string{"pending.example.test", "outside.example.test", "READY.example.test"} {
		if _, _, err := PublishHostname("", "api", selected, current); err == nil {
			t.Fatalf("unavailable or invalid domain %q was accepted", selected)
		}
	}
	// an exact hostname chooses its own ready domain, regardless of the configured default.
	hostname, domain, err = PublishHostname("ready.example.test", "", "pending.example.test", current)
	if err != nil || hostname != "ready.example.test" || domain.Id != "domain_ready" {
		t.Fatalf("exact hostname = %q, %+v, %v", hostname, domain, err)
	}
	for _, invalid := range []string{"http://ready.example.test", "https://ready.example.test", "https://ready.example.test/", "ready.example.test:443"} {
		if _, _, err := PublishHostname(invalid, "", "", current); err == nil {
			t.Fatalf("invalid hostname %q was accepted", invalid)
		}
	}
}
