package controlapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	tnldconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestLocalPublishRunCertificatePlan(t *testing.T) {
	for _, test := range []struct {
		name, kind, scope string
		dnsAutomation     bool
		nested            bool
		simpleTeamShared  bool
		maxChildLabels    int
		expectDepthDenied bool
	}{
		{name: "managed_member_dns", kind: "managed", scope: "member", dnsAutomation: true, maxChildLabels: 1},
		{name: "custom_member_dns", kind: "custom", scope: "member", dnsAutomation: true, maxChildLabels: 1},
		{name: "managed_member_no_dns", kind: "managed", scope: "member"},
		{name: "custom_member_no_dns", kind: "custom", scope: "member"},
		{name: "shared_dns", kind: "custom", scope: "shared", dnsAutomation: true, maxChildLabels: 1},
		{name: "simple_team_shared_dns", kind: "managed", scope: "shared", dnsAutomation: true, simpleTeamShared: true},
		{name: "generated_team_shared_dns", kind: "managed", scope: "shared", dnsAutomation: true},
		{name: "shared_no_dns", kind: "custom", scope: "shared"},
		{name: "nested_managed_dns", kind: "managed", scope: "member", dnsAutomation: true, nested: true},
		{name: "nested_managed_manual_dns", kind: "managed", scope: "member", nested: true},
		{name: "nested_custom_domain", kind: "custom", scope: "member", dnsAutomation: true, nested: true, maxChildLabels: 1},
		{name: "nested_managed_limited", kind: "managed", scope: "member", dnsAutomation: true, nested: true, maxChildLabels: 1, expectDepthDenied: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			namespace := "member.routes.example.test"
			if test.kind == "managed" {
				namespace = "member-unique.routes.example.test"
			}
			if test.kind == "managed" && test.scope == "shared" {
				namespace = "team-generated.routes.example.test"
				if test.simpleTeamShared {
					namespace = "studio.routes.example.test"
				}
			}
			hostname := "api." + namespace
			if test.nested {
				hostname = "api.shop." + namespace
			}
			membershipID := "membership_1"
			if test.scope == "shared" {
				hostname, membershipID = "shared.routes.example.test", ""
				if test.kind == "managed" {
					hostname = "shared." + namespace
				}
			}
			teamKind := controlstate.TeamKindOrganization
			mode := naming.ManagedURLModeGenerated
			if test.simpleTeamShared {
				teamKind, mode = controlstate.TeamKindPersonal, naming.ManagedURLModeSimple
			}
			store := &certificatePlanStoreStub{
				publicURLMutationStoreStub: publicURLMutationStoreStub{
					route: controlstate.PublicURL{
						ID: "public_url_1", TeamID: "team_1", DomainID: "domain_1", MembershipID: membershipID,
						CanonicalHostname: hostname, Target: "http://127.0.0.1:3000",
						PublicURLScope: controlstate.PublicURLScope(test.scope), MutationRevision: 1, AuthorizationPublishRunNumber: 1,
					},
					sessionSetup: controlstate.PublishRunSetup{PublishRunID: "session_1", PublicURLID: "public_url_1", PublishRunNumber: 1},
				},
				auth: localAuthorizationStoreStub{
					principal: controlstate.ControlPrincipal{IdentityID: "identity_1", RetrySecret: [32]byte{1}},
					identity: controlstate.IdentityContext{Memberships: []controlstate.Membership{{
						ID: "membership_1", TeamID: "team_1", TeamKind: teamKind, TeamDisplayName: "studio", Role: "owner", PolicyRevision: 1,
						MemberSlug: "member", ManagedLabel: "member-unique", TeamManagedLabel: "team-generated",
					}}},
					domains: []controlstate.Domain{{ID: "domain_1", Kind: controlstate.DomainKind(test.kind), State: controlstate.DomainReady,
						CanonicalDomain: "routes.example.test", DNSAuthorityReference: "dns_authority_1"}},
				},
			}
			authorizer := localAuthorizer{store: store, dnsAutomation: test.dnsAutomation, managedURLMode: mode, managedDomainMaxMemberChildLabels: test.maxChildLabels}
			decision, err := authorizer.Authorize(t.Context(), authorization.Request{Operation: authorization.OperationPublishRunCreate, AccessToken: "access-token", TeamID: "team_1", DomainID: "domain_1", PublicURLID: "public_url_1", PublicURLMembershipID: membershipID, CanonicalHostname: hostname, PublicURLScope: authorization.PublicURLScope(test.scope), PublicURLMutationRevision: 1})
			if test.expectDepthDenied {
				if !errors.Is(err, errMemberHostnameDepth) {
					t.Fatalf("nested hostname depth rejection = %v", err)
				}
				return
			}
			if err != nil || decision.CertificatePlan == nil {
				t.Fatalf("certificate boundary = %+v, %v", decision, err)
			}
			wantScope, wantIDs := hostname, []string{hostname}
			if test.dnsAutomation {
				wantScope = namespace
				if test.scope == "shared" {
					wantScope, wantIDs = "routes.example.test", []string{"routes.example.test", "*.routes.example.test"}
					if test.kind == "managed" {
						wantScope, wantIDs = namespace, []string{"*." + namespace}
					}
				} else {
					if test.nested {
						wantScope = "shop." + namespace
					}
					wantIDs = []string{"*." + wantScope}
				}
			}
			plan := *decision.CertificatePlan
			slices.Sort(wantIDs)
			if plan.CacheKey != wantScope || plan.Scope != wantScope || !slices.Equal(plan.Identifiers, wantIDs) {
				t.Errorf("API plan = %#v; want cache key/scope %q and identifiers %q", plan, wantScope, wantIDs)
			}
			if test.dnsAutomation && string(plan.ChallengeMethod) != "dns-01" {
				t.Errorf("DNS challenge method = %q; want dns-01", plan.ChallengeMethod)
			}
			if !test.dnsAutomation && string(plan.ChallengeMethod) != "dns-01" {
				t.Errorf("exact-host challenge method = %q; want dns-01", plan.ChallengeMethod)
			}
		})
	}
}

func TestControlDiscoverySeparatesRouteAndRelayDNSAutomation(t *testing.T) {
	for _, test := range []struct {
		name, managedZone, serverZone string
		want                          bool
	}{
		{"no_zones", "", "", false},
		{"managed_only", "ZMANAGED", "", true},
		{"server_only", "", "ZSERVER", false},
		{"both", "ZMANAGED", "ZSERVER", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := tnldconfig.Config{Role: tnldconfig.RoleControl, ServerDomain: "infra.example.test",
				ManagedDomain: "routes.other.test", Route53ManagedZoneID: test.managedZone, Route53ServerZoneID: test.serverZone}
			h := testHandler(t, Config{ManagedDomain: cfg.ManagedDomain,
				ControlURL: "https://" + cfg.ServerHostname(), DNSAutomation: cfg.DNSAutomationEnabled()}, nil, nil, nil)
			response := httptest.NewRecorder()
			h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/discovery", nil))
			var discovery controlv1.ControlDiscovery
			if err := json.Unmarshal(response.Body.Bytes(), &discovery); err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusOK || discovery.DnsAutomation != test.want ||
				discovery.ManagedDomain != "routes.other.test" {
				t.Fatalf("discovery status = %d, facts = %#v", response.Code, discovery)
			}
		})
	}
}

type certificatePlanStoreStub struct {
	publicURLMutationStoreStub
	auth           localAuthorizationStoreStub
	sessionRequest controlstate.PublishRunRequest
}

func (s *certificatePlanStoreStub) AuthorizeTeamSession(ctx context.Context, p controlstate.ControlPrincipal, team string, now time.Time) error {
	return s.auth.AuthorizeTeamSession(ctx, p, team, now)
}

func (s *certificatePlanStoreStub) AuthenticateAccessToken(ctx context.Context, token credentials.AccessToken, now time.Time) (controlstate.ControlPrincipal, error) {
	return s.auth.AuthenticateAccessToken(ctx, token, now)
}

func (s *certificatePlanStoreStub) IdentityContext(ctx context.Context, identityID string) (controlstate.IdentityContext, error) {
	return s.auth.IdentityContext(ctx, identityID)
}

func (s *certificatePlanStoreStub) ListTeamDomains(ctx context.Context, identityID, teamID string) ([]controlstate.Domain, error) {
	return s.auth.ListTeamDomains(ctx, identityID, teamID)
}

func (s *certificatePlanStoreStub) CreatePublishRun(_ context.Context, request controlstate.PublishRunRequest, _ time.Time, _, _ time.Duration) (controlstate.PublishRunSetup, error) {
	s.sessionRequest = request
	return s.sessionSetup, nil
}
