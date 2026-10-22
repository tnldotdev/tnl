package resolve

import (
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestProjectPublishHostnameUsesNamespace(t *testing.T) {
	current := team.NewContext(
		authorityv1.Team{Id: "team_1", DefaultDomainId: "domain_1", PolicyRevision: 4},
		authorityv1.Membership{Id: "membership_1", TeamId: "team_1", Role: authorityv1.TeamRoleMember, MemberSlug: "chase", ManagedLabel: "chase-abc"},
		[]authorityv1.Domain{{Id: "domain_1", Kind: authorityv1.Managed, CanonicalDomain: "tnl.dev", State: authorityv1.DomainStateReady}}, "",
	)
	hostname, domain, scope, err := PublishHostname("", "api", "", current)
	if err != nil {
		t.Fatal(err)
	}
	if hostname != "api.chase-abc.tnl.dev" || domain.Id != "domain_1" || scope != controlv1.Member {
		t.Fatalf("resolution = %q, %#v, %q", hostname, domain, scope)
	}
	if _, _, _, err := PublishHostname("https://shared.tnl.dev", "", "", current); err == nil {
		t.Fatal("member was allowed to create a shared route")
	}
	generated, _, generatedScope, err := PublishHostname("", "", "", current)
	if err != nil {
		t.Fatal(err)
	}
	label, found := strings.CutSuffix(generated, ".chase-abc.tnl.dev")
	if !found || strings.Count(label, "-") != 1 || generatedScope != controlv1.Member {
		t.Fatalf("generated route = %q, %q", generated, generatedScope)
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
			name, wantHost, wantScope := "api", "api."+namespace, controlv1.Member
			if test.host != "" {
				name, wantHost, wantScope = "", test.host, controlv1.Shared
			}
			publicURL := ""
			if test.host != "" {
				publicURL = "https://" + test.host
			}
			inputs := []string{publicURL}
			if test.host != "" {
				inputs = append(inputs, test.host)
			}
			for _, input := range inputs {
				hostname, domain, scope, err := PublishHostname(input, name, "", current)
				if err != nil {
					t.Fatal(err)
				}
				if hostname != wantHost || domain.Id != "domain_1" || scope != wantScope {
					t.Fatalf("resolution = %q, %q, %q; want %q, %q", hostname, domain.Id, scope, wantHost, wantScope)
				}
			}
		})
	}
}

func TestProjectManagedAndCustomDefaultURLShapes(t *testing.T) {
	for _, test := range []struct {
		name, mode, teamKind, domainKind, teamName, domain, want, scope string
	}{
		{"personal_managed", "simple", "personal", "managed", "alex", "routes.example.test", "app.alex.routes.example.test", "member"},
		{"organization_managed", "simple", "organization", "managed", "studio", "routes.example.test", "app.alex.studio.routes.example.test", "member"},
		{"personal_custom", "simple", "personal", "custom", "alex", "dev.example.test", "app.dev.example.test", "shared"},
		{"organization_custom", "simple", "organization", "custom", "studio", "studio.example.test", "app.alex.studio.example.test", "member"},
		{"hosted_generated", "generated", "organization", "managed", "studio", "tnl.dev", "app.ecstatic-penguin.tnl.dev", "member"},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := team.NewContext(
				authorityv1.Team{Id: "team", Kind: authorityv1.TeamKind(test.teamKind), DisplayName: test.teamName, DefaultDomainId: "domain"},
				authorityv1.Membership{Id: "member", TeamId: "team", Role: authorityv1.TeamRoleOwner,
					MemberSlug: "alex", ManagedLabel: "ecstatic-penguin"},
				[]authorityv1.Domain{{Id: "domain", Kind: authorityv1.DomainKind(test.domainKind),
					CanonicalDomain: test.domain, State: authorityv1.DomainStateReady}},
				naming.ManagedURLMode(test.mode),
			)
			hostname, _, scope, err := PublishHostname("", "app", "", current)
			if err != nil || hostname != test.want || string(scope) != test.scope {
				t.Fatalf("hostname=%q scope=%q error=%v; want %q %q", hostname, scope, err, test.want, test.scope)
			}
			if test.scope == "member" {
				namespace, _ := current.Namespace(current.Domains()[0])
				if _, _, _, err := PublishHostname("https://"+namespace, "", "", current); err == nil {
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
	hostname, domain, scope, err := PublishHostname("https://api.member.ready.example.test", "", "", current)
	if err != nil || hostname != "api.member.ready.example.test" || domain.Id != "domain_ready" || scope != controlv1.Member {
		t.Fatalf("explicit hostname = %q, %+v, %q, %v", hostname, domain, scope, err)
	}
	if _, _, _, err := PublishHostname("", "api", "", current); err == nil {
		t.Fatal("default-domain name was accepted while its domain is pending")
	} else if reason, _, ok := failure.Describe(err); !ok || reason != failure.DomainNotReady {
		t.Fatalf("pending domain reason = %q, %v", reason, err)
	}
	hostname, domain, scope, err = PublishHostname("", "api", "ready.example.test", current)
	if err != nil || hostname != "api.member.ready.example.test" || domain.Id != "domain_ready" || scope != controlv1.Member {
		t.Fatalf("project domain = %q, %+v, %q, %v", hostname, domain, scope, err)
	}
	for _, selected := range []string{"pending.example.test", "outside.example.test", "READY.example.test"} {
		if _, _, _, err := PublishHostname("", "api", selected, current); err == nil {
			t.Fatalf("unavailable or invalid domain %q was accepted", selected)
		}
	}
	// an exact public URL chooses its own ready domain, regardless of the configured domain.
	hostname, domain, scope, err = PublishHostname("https://ready.example.test", "", "pending.example.test", current)
	if err != nil || hostname != "ready.example.test" || domain.Id != "domain_ready" || scope != controlv1.Shared {
		t.Fatalf("exact public URL = %q, %+v, %q, %v", hostname, domain, scope, err)
	}
	for _, invalid := range []string{"http://ready.example.test", "https://ready.example.test/", "https://ready.example.test:443"} {
		if _, _, _, err := PublishHostname(invalid, "", "", current); err == nil {
			t.Fatalf("invalid public URL %q was accepted", invalid)
		}
	}
}
