package main

import (
	"context"
	"errors"
	"reflect"
	"testing"

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
	policy, current, err := resolveIPPolicy(t.Context(), lookup, []string{"198.51.100.8/24"}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.4/32", "198.51.100.0/24"}
	if current != "192.0.2.4" || !reflect.DeepEqual(policy, want) || lookup.calls != 1 {
		t.Fatalf("policy = %#v, current = %q, calls = %d", policy, current, lookup.calls)
	}
}

func TestResolveIPPolicyDoesNotDuplicateExplicitCurrentIP(t *testing.T) {
	lookup := &testClientIPLookup{response: controlv1.ClientIPResponse{Ip: "192.0.2.4"}}
	policy, current, err := resolveIPPolicy(t.Context(), lookup, []string{"192.0.2.4/32"}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.4/32"}
	if current != "192.0.2.4" || !reflect.DeepEqual(policy, want) || lookup.calls != 1 {
		t.Fatalf("policy = %#v, current = %q, calls = %d", policy, current, lookup.calls)
	}
}

func TestResolveIPPolicyPublicDoesNotLookUpCurrentIP(t *testing.T) {
	lookup := &testClientIPLookup{err: errors.New("must not be called")}
	policy, current, err := resolveIPPolicy(t.Context(), lookup, nil, true)
	if err != nil || policy == nil || len(policy) != 0 || current != "" || lookup.calls != 0 {
		t.Fatalf("policy = %#v, current = %q, calls = %d, error = %v", policy, current, lookup.calls, err)
	}
}

func TestResolveIPPolicyFailsWhenCurrentIPCannotBeResolved(t *testing.T) {
	lookup := &testClientIPLookup{err: errors.New("unavailable")}
	if _, _, err := resolveIPPolicy(t.Context(), lookup, nil, false); err == nil {
		t.Fatal("current-IP lookup failure was accepted")
	}
}

func TestPublisherConfigPreservesEphemeralRouteChoice(t *testing.T) {
	configured := (publisherServices{ephemeral: true}).config("http://127.0.0.1:3000", nil, 750)
	if !configured.Ephemeral {
		t.Fatal("ephemeral route choice was not passed to the publisher")
	}
	if configured.RequestLimit != 750 {
		t.Fatalf("request limit = %d", configured.RequestLimit)
	}
}

func TestPublishHostnameScopeMatrix(t *testing.T) {
	for _, test := range []struct {
		name, kind, host string
	}{
		{"managed", "managed", ""},
		{"claimed", "claimed", ""},
		{"shared", "claimed", "shared.routes.example.test"},
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
			subdomain, wantHost, wantScope := "api", "api."+namespace, controlv1.Member
			if test.host != "" {
				subdomain, wantHost, wantScope = "", test.host, controlv1.Shared
			}
			hostname, domain, scope, err := resolvePublishHostname(test.host, subdomain, current)
			if err != nil {
				t.Fatal(err)
			}
			if hostname != wantHost || domain.Id != "domain_1" || scope != wantScope {
				t.Fatalf("resolution = %q, %q, %q; want %q, %q", hostname, domain.Id, scope, wantHost, wantScope)
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
			{Id: "domain_ready", CanonicalDomain: "ready.example.test", Kind: authorityv1.Claimed, State: authorityv1.DomainStateReady},
		},
	}
	hostname, domain, scope, err := resolvePublishHostname("api.member.ready.example.test", "", current)
	if err != nil || hostname != "api.member.ready.example.test" || domain.Id != "domain_ready" || scope != controlv1.Member {
		t.Fatalf("explicit hostname = %q, %+v, %q, %v", hostname, domain, scope, err)
	}
	if _, _, _, err := resolvePublishHostname("", "api", current); err == nil {
		t.Fatal("default-domain subdomain was accepted while its domain is pending")
	}
}
