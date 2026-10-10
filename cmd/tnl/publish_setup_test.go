package main

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type testClientIPLookup struct {
	response controlv1.ClientIPResponse
	err      error
	calls    int
}

func (l *testClientIPLookup) ClientIP(context.Context) (controlv1.ClientIPResponse, error) {
	l.calls++
	return l.response, l.err
}

func TestResolveIPPolicyDefaultsToCurrentIPAndAddsExplicitPrefixes(t *testing.T) {
	lookup := &testClientIPLookup{response: controlv1.ClientIPResponse{Ip: "192.0.2.4"}}
	policy, err := resolveIPPolicy(t.Context(), lookup, []string{"198.51.100.8/24"}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.4/32", "198.51.100.0/24"}
	if policy.current != "192.0.2.4" || !reflect.DeepEqual(policy.prefixes, want) || lookup.calls != 1 {
		t.Fatalf("policy = %#v, calls = %d", policy, lookup.calls)
	}
}

func TestResolveIPPolicyDoesNotDuplicateExplicitCurrentIP(t *testing.T) {
	lookup := &testClientIPLookup{response: controlv1.ClientIPResponse{Ip: "192.0.2.4"}}
	policy, err := resolveIPPolicy(t.Context(), lookup, []string{"192.0.2.4/32"}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.4/32"}
	if policy.current != "192.0.2.4" || !reflect.DeepEqual(policy.prefixes, want) || lookup.calls != 1 {
		t.Fatalf("policy = %#v, calls = %d", policy, lookup.calls)
	}
}

func TestResolveIPPolicyPublicDoesNotLookUpCurrentIP(t *testing.T) {
	lookup := &testClientIPLookup{err: errors.New("must not be called")}
	policy, err := resolveIPPolicy(t.Context(), lookup, nil, true)
	if err != nil || policy.prefixes == nil || len(policy.prefixes) != 0 || policy.current != "" || lookup.calls != 0 {
		t.Fatalf("policy = %#v, calls = %d, error = %v", policy, lookup.calls, err)
	}
}

func TestResolveIPPolicyFailsWhenCurrentIPCannotBeResolved(t *testing.T) {
	lookup := &testClientIPLookup{err: errors.New("unavailable")}
	if _, err := resolveIPPolicy(t.Context(), lookup, nil, false); err == nil {
		t.Fatal("current-IP lookup failure was accepted")
	}
}

func TestPublisherConfigPreservesEphemeralRouteChoice(t *testing.T) {
	configured := (publisherServices{ephemeral: true}).config("http://127.0.0.1:3000", nil, publisher.ApplicationLimits{Concurrency: 750})
	if !configured.Ephemeral {
		t.Fatal("ephemeral route choice was not passed to the publisher")
	}
	if configured.Limits.Concurrency != 750 {
		t.Fatalf("concurrency = %d", configured.Limits.Concurrency)
	}
}

func TestPublishHostnameScopeMatrix(t *testing.T) {
	for _, test := range []struct {
		name, kind, host string
	}{
		{"managed", "managed", ""},
		{"custom", "custom", ""},
		{"shared", "custom", "shared.routes.example.test"},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := teamContext{
				team: authorityv1.Team{Id: "team_1", DefaultDomainId: "domain_1", PolicyRevision: 1},
				membership: authorityv1.Membership{Id: "membership_1", TeamId: "team_1", Role: authorityv1.TeamRoleOwner,
					MemberSlug: "member", ManagedLabel: "member-unique"},
				domains: []authorityv1.Domain{{Id: "domain_1", Kind: authorityv1.DomainKind(test.kind),
					CanonicalDomain: "routes.example.test", State: authorityv1.DomainStateReady}},
			}
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
				hostname, domain, scope, err := resolvePublishHostname(input, name, "", current)
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

func TestManagedAndCustomDefaultURLShapes(t *testing.T) {
	for _, test := range []struct {
		name, mode, teamKind, domainKind, teamName, domain, want, scope string
		builtin                                                         bool
	}{
		{"builtin_managed", "simple", "personal", "managed", "local-administrator", "routes.example.test", "app.routes.example.test", "shared", true},
		{"personal_managed", "simple", "personal", "managed", "alex", "routes.example.test", "app.alex.routes.example.test", "member", false},
		{"organization_managed", "simple", "organization", "managed", "studio", "routes.example.test", "app.alex.studio.routes.example.test", "member", false},
		{"personal_custom", "simple", "personal", "custom", "alex", "dev.example.test", "app.dev.example.test", "shared", false},
		{"organization_custom", "simple", "organization", "custom", "studio", "studio.example.test", "app.alex.studio.example.test", "member", false},
		{"hosted_generated", "generated", "organization", "managed", "studio", "tnl.dev", "app.ecstatic-penguin.tnl.dev", "member", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := teamContext{
				team: authorityv1.Team{Id: "team", Kind: authorityv1.TeamKind(test.teamKind), DisplayName: test.teamName, DefaultDomainId: "domain"},
				membership: authorityv1.Membership{Id: "member", TeamId: "team", Role: authorityv1.TeamRoleOwner,
					MemberSlug: "alex", ManagedLabel: "ecstatic-penguin"},
				domains: []authorityv1.Domain{{Id: "domain", Kind: authorityv1.DomainKind(test.domainKind),
					CanonicalDomain: test.domain, State: authorityv1.DomainStateReady}},
				mode: naming.ManagedURLMode(test.mode), builtin: test.builtin,
			}
			hostname, _, scope, err := resolvePublishHostname("", "app", "", current)
			if err != nil || hostname != test.want || string(scope) != test.scope {
				t.Fatalf("hostname=%q scope=%q error=%v; want %q %q", hostname, scope, err, test.want, test.scope)
			}
			if test.scope == "member" {
				namespace := namespaceForMembership(current, current.domains[0])
				if _, _, _, err := resolvePublishHostname("https://"+namespace, "", "", current); err == nil {
					t.Fatal("member namespace apex was accepted")
				}
			}
		})
	}
}

func TestExplicitHostnameUsesReadyDomainWhenDefaultIsPending(t *testing.T) {
	current := teamContext{
		team: authorityv1.Team{Id: "team_1", DefaultDomainId: "domain_pending"},
		membership: authorityv1.Membership{Id: "membership_1", TeamId: "team_1",
			Role: authorityv1.TeamRoleOwner, MemberSlug: "member", ManagedLabel: "managed-member"},
		domains: []authorityv1.Domain{
			{Id: "domain_pending", CanonicalDomain: "pending.example.test", State: authorityv1.DomainStatePending},
			{Id: "domain_ready", CanonicalDomain: "ready.example.test", Kind: authorityv1.Custom, State: authorityv1.DomainStateReady},
		},
	}
	hostname, domain, scope, err := resolvePublishHostname("https://api.member.ready.example.test", "", "", current)
	if err != nil || hostname != "api.member.ready.example.test" || domain.Id != "domain_ready" || scope != controlv1.Member {
		t.Fatalf("explicit hostname = %q, %+v, %q, %v", hostname, domain, scope, err)
	}
	if _, _, _, err := resolvePublishHostname("", "api", "", current); err == nil {
		t.Fatal("default-domain name was accepted while its domain is pending")
	} else if reason, _, ok := failure.Describe(err); !ok || reason != failure.DomainNotReady {
		t.Fatalf("pending domain reason = %q, %v", reason, err)
	}
	hostname, domain, scope, err = resolvePublishHostname("", "api", "ready.example.test", current)
	if err != nil || hostname != "api.member.ready.example.test" || domain.Id != "domain_ready" || scope != controlv1.Member {
		t.Fatalf("project domain = %q, %+v, %q, %v", hostname, domain, scope, err)
	}
	for _, selected := range []string{"pending.example.test", "outside.example.test", "READY.example.test"} {
		if _, _, _, err := resolvePublishHostname("", "api", selected, current); err == nil {
			t.Fatalf("unavailable or invalid domain %q was accepted", selected)
		}
	}
	// an exact public URL chooses its own ready domain, regardless of the configured domain.
	hostname, domain, scope, err = resolvePublishHostname("https://ready.example.test", "", "pending.example.test", current)
	if err != nil || hostname != "ready.example.test" || domain.Id != "domain_ready" || scope != controlv1.Shared {
		t.Fatalf("exact public URL = %q, %+v, %q, %v", hostname, domain, scope, err)
	}
	for _, invalid := range []string{"http://ready.example.test", "https://ready.example.test/", "https://ready.example.test:443"} {
		if _, _, _, err := resolvePublishHostname(invalid, "", "", current); err == nil {
			t.Fatalf("invalid public URL %q was accepted", invalid)
		}
	}
}
