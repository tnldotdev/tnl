package controlapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestBuiltinPublishRunCertificatePlan(t *testing.T) {
	for _, test := range []struct {
		name, kind, scope string
		dnsAutomation     bool
		nested            bool
		simpleDirect      bool
		maxChildLabels    int
		expectDepthDenied bool
	}{
		{name: "managed_member_dns", kind: "managed", scope: "member", dnsAutomation: true, maxChildLabels: 1},
		{name: "custom_member_dns", kind: "custom", scope: "member", dnsAutomation: true, maxChildLabels: 1},
		{name: "managed_member_no_dns", kind: "managed", scope: "member"},
		{name: "custom_member_no_dns", kind: "custom", scope: "member"},
		{name: "shared_dns", kind: "custom", scope: "shared", dnsAutomation: true, maxChildLabels: 1},
		{name: "simple_direct_dns", kind: "managed", scope: "shared", dnsAutomation: true, simpleDirect: true},
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
			hostname := "api." + namespace
			if test.nested {
				hostname = "api.shop." + namespace
			}
			membershipID := "membership_1"
			if test.scope == "shared" {
				hostname, membershipID = "shared.routes.example.test", ""
			}
			teamKind := controlstate.TeamKindOrganization
			mode := naming.ManagedURLModeGenerated
			if test.simpleDirect {
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
					principal: controlstate.ControlPrincipal{IdentityID: "identity_1", Administrator: test.simpleDirect, RetrySecret: [32]byte{1}},
					identity: controlstate.IdentityContext{Memberships: []controlstate.Membership{{
						ID: "membership_1", TeamID: "team_1", TeamKind: teamKind, TeamDisplayName: "studio", Role: "owner", PolicyRevision: 1,
						MemberSlug: "member", ManagedLabel: "member-unique",
					}}},
					domains: []controlstate.Domain{{ID: "domain_1", Kind: controlstate.DomainKind(test.kind), State: controlstate.DomainReady,
						CanonicalDomain: "routes.example.test", DNSAuthorityReference: "dns_authority_1"}},
				},
			}
			h := testHandler(t, Config{DNSAutomation: test.dnsAutomation, ManagedURLMode: mode,
				ManagedDomainMaxMemberChildLabels: test.maxChildLabels}, store, store, nil)
			request := httptest.NewRequest(http.MethodPost, "/v1/public-urls/public_url_1/publish-runs", nil)
			request.Header.Set("Authorization", "Bearer access-token")
			request.Header.Set("Idempotency-Key", "session-plan")
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request)
			if test.expectDepthDenied {
				var problem controlv1.Problem
				if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil || response.Code != http.StatusForbidden || problem.Code != controlv1.MemberHostnameDepthExceeded || store.sessions != 0 {
					t.Fatalf("nested hostname was not rejected before creating a run: %d %s", response.Code, response.Body.String())
				}
				return
			}
			if response.Code != http.StatusCreated {
				t.Fatalf("session status = %d: %s", response.Code, response.Body.String())
			}
			var setup controlv1.PublishRunSetup
			if err := json.Unmarshal(response.Body.Bytes(), &setup); err != nil {
				t.Fatal(err)
			}
			wantScope, wantIDs := hostname, []string{hostname}
			if test.dnsAutomation {
				wantScope = namespace
				if test.scope == "shared" {
					wantScope, wantIDs = "routes.example.test", []string{"routes.example.test", "*.routes.example.test"}
					if test.simpleDirect {
						wantIDs = []string{"*.routes.example.test"}
					}
				} else {
					if test.nested {
						wantScope = "shop." + namespace
					}
					wantIDs = []string{"*." + wantScope}
				}
			}
			plan := setup.CertificatePlan
			slices.Sort(wantIDs)
			if plan.CacheKey != wantScope || plan.Scope != wantScope || !slices.Equal(plan.Identifiers, wantIDs) {
				t.Errorf("API plan = %#v; want cache key/scope %q and identifiers %q", plan, wantScope, wantIDs)
			}
			if store.sessionRequest.CertificateScope != wantScope || store.sessionRequest.CertificateCacheKey != wantScope ||
				!slices.Equal(store.sessionRequest.CertificateIdentifiers, wantIDs) {
				t.Errorf("persisted plan = %q, %q, %q; want %q, %q", store.sessionRequest.CertificateCacheKey,
					store.sessionRequest.CertificateScope, store.sessionRequest.CertificateIdentifiers, wantScope, wantIDs)
			}
			if test.dnsAutomation && plan.ChallengeMethod != controlv1.Dns01 {
				t.Errorf("DNS challenge method = %q; want dns-01", plan.ChallengeMethod)
			}
			if string(store.sessionRequest.CertificateChallenge) != string(plan.ChallengeMethod) {
				t.Errorf("stored challenge method = %q; API returned %q", store.sessionRequest.CertificateChallenge, plan.ChallengeMethod)
			}
			if !test.dnsAutomation && plan.ChallengeMethod != controlv1.TlsAlpn01 {
				t.Errorf("no-DNS challenge method = %q; want tls-alpn-01", plan.ChallengeMethod)
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

func (s *certificatePlanStoreStub) AuthenticateAccessToken(ctx context.Context, token credentials.AccessToken, revision int64, now time.Time) (controlstate.ControlPrincipal, error) {
	return s.auth.AuthenticateAccessToken(ctx, token, revision, now)
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
