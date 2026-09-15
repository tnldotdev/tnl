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
	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestBuiltinRouteSessionCertificatePlan(t *testing.T) {
	for _, test := range []struct {
		name, kind, scope string
		dns               bool
	}{
		{"managed_member_dns", "managed", "member", true},
		{"claimed_member_dns", "claimed", "member", true},
		{"managed_member_no_dns", "managed", "member", false},
		{"claimed_member_no_dns", "claimed", "member", false},
		{"shared_dns", "managed", "shared", true},
		{"shared_no_dns", "claimed", "shared", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			namespace := "member.routes.example.test"
			if test.kind == "managed" {
				namespace = "member-unique.routes.example.test"
			}
			hostname := "api." + namespace
			membershipID := "membership_1"
			if test.scope == "shared" {
				hostname, membershipID = "shared.routes.example.test", ""
			}
			store := &certificatePlanStoreStub{
				routeMutationStoreStub: routeMutationStoreStub{
					route: controlstate.Route{
						ID: "route_1", TeamID: "team_1", DomainID: "domain_1", MembershipID: membershipID,
						CanonicalHostname: hostname, Target: "http://127.0.0.1:3000",
						RouteScope: controlstate.RouteScope(test.scope), MutationRevision: 1, AuthorizationRouteVersion: 1,
					},
					sessionSetup: controlstate.RouteSessionSetup{RouteSessionID: "session_1", RouteID: "route_1", RouteVersion: 1},
				},
				auth: localAuthorizationStoreStub{
					principal: controlstate.ControlPrincipal{IdentityID: "identity_1", RetrySecret: [32]byte{1}},
					identity: controlstate.IdentityContext{Memberships: []controlstate.Membership{{
						ID: "membership_1", TeamID: "team_1", Role: "owner", PolicyRevision: 1,
						MemberSlug: "member", ManagedLabel: "member-unique",
					}}},
					domains: []controlstate.Domain{{ID: "domain_1", Kind: test.kind, State: "ready",
						CanonicalDomain: "routes.example.test", DNSAuthorityReference: "dns_authority_1"}},
				},
			}
			h := NewHandler(Config{DNSAutomation: test.dns}, store, store, nil)
			request := httptest.NewRequest(http.MethodPost, "/v1/routes/route_1/sessions", nil)
			request.Header.Set("Authorization", "Bearer access-token")
			request.Header.Set("Idempotency-Key", "session-plan")
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request)
			if response.Code != http.StatusCreated {
				t.Fatalf("session status = %d: %s", response.Code, response.Body.String())
			}
			var setup controlv1.RouteSessionSetup
			if err := json.Unmarshal(response.Body.Bytes(), &setup); err != nil {
				t.Fatal(err)
			}
			wantScope, wantIDs := hostname, []string{hostname}
			if test.dns && test.scope == "member" {
				wantScope, wantIDs = namespace, []string{namespace, "*." + namespace}
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
			if test.dns && plan.ChallengeMethod != controlv1.Dns01 {
				t.Errorf("DNS challenge method = %q; want dns-01", plan.ChallengeMethod)
			}
			if store.sessionRequest.CertificateChallenge != string(plan.ChallengeMethod) {
				t.Errorf("stored challenge method = %q; API returned %q", store.sessionRequest.CertificateChallenge, plan.ChallengeMethod)
			}
			if !test.dns && plan.ChallengeMethod != controlv1.TlsAlpn01 {
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
			cfg := tnldconfig.Config{Mode: tnldconfig.RoleControl, ServerDomain: "infra.example.test",
				ManagedDeploymentDomain: "routes.other.test", Route53ManagedZoneID: test.managedZone, Route53ServerZoneID: test.serverZone}
			h := NewHandler(Config{ManagedDeploymentDomain: cfg.ManagedDomain(),
				AuthorityEndpoint: "https://" + cfg.ServerHostname(), DNSAutomation: cfg.DNSAutomationEnabled()}, nil, nil, nil)
			response := httptest.NewRecorder()
			h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/discovery", nil))
			var discovery controlv1.ControlDiscovery
			if err := json.Unmarshal(response.Body.Bytes(), &discovery); err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusOK || discovery.DnsAutomation != test.want ||
				discovery.ManagedDeploymentDomain != "routes.other.test" || discovery.AuthorityEndpoint != "https://control.infra.example.test" {
				t.Fatalf("discovery status = %d, facts = %#v", response.Code, discovery)
			}
		})
	}
}

type certificatePlanStoreStub struct {
	routeMutationStoreStub
	auth           localAuthorizationStoreStub
	sessionRequest controlstate.RouteSessionRequest
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

func (s *certificatePlanStoreStub) CreateRouteSession(_ context.Context, request controlstate.RouteSessionRequest, _ time.Time, _, _ time.Duration) (controlstate.RouteSessionSetup, error) {
	s.sessionRequest = request
	return s.sessionSetup, nil
}
