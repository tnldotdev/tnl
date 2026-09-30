package controlapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestHostedAuthorizerSendsServiceSecretAndReturnsControlDecision(t *testing.T) {
	const serviceSecret = "0123456789abcdef0123456789abcdef"
	type observedRequest struct {
		method, path, authorization string
		body                        authorityv1.ServiceAuthorizationRequest
		err                         error
	}
	received := make(chan observedRequest, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body authorityv1.ServiceAuthorizationRequest
		err := json.NewDecoder(request.Body).Decode(&body)
		received <- observedRequest{request.Method, request.URL.Path, request.Header.Get("Authorization"), body, err}
		writeJSON(response, http.StatusOK, authorityv1.ServiceAuthorizationDecision{
			IdentityId: "identity_1", TeamId: "team_1", ActingMembershipId: "membership_1",
			ActingRole: authorityv1.TeamRoleOwner, PublicUrlMembershipId: pointer("membership_1"), PolicyRevision: 4,
			DomainId: "domain_1", CanonicalHostname: "api.example.test", PublicUrlScope: authorityv1.PublicURLScopeMember,
			DnsAuthorityReference: "dns_authority_1", CertificatePlan: &authorityv1.CertificatePlan{
				CacheKey: "example.test", Scope: "example.test", Identifiers: []string{"*.example.test", "example.test"},
				ChallengeMethod: authorityv1.Dns01,
			},
		})
	}))
	defer server.Close()
	client, err := authorityclient.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	retrySecret := [32]byte{1, 2, 3}
	authorizer := hostedAuthorizer{client: client, secret: serviceSecret, store: externalPrincipalStoreStub{secret: retrySecret}}
	decision, err := authorizer.Authorize(t.Context(), authorization.Request{
		AccessToken: "opaque-user-token", Operation: authorization.OperationPublishRunCreate,
		TeamID: "team_1", PublicURLMembershipID: "membership_1", DomainID: "domain_1",
		CanonicalHostname: "api.example.test", PublicURLScope: "member", Target: "http://127.0.0.1:3000",
		AllowedIPPrefixes: []string{"192.0.2.0/24"}, PublicURLID: "public_url_1", PublishRunNumber: 2,
		PublicURLMutationRevision: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if got.err != nil || got.method != http.MethodPost || got.path != "/v1/service/authorize" || got.authorization != "Bearer "+serviceSecret {
			t.Fatalf("request = %#v", got)
		}
		body := got.body
		if body.AccessToken != "opaque-user-token" || body.Operation != authorityv1.PublishRunCreate ||
			body.PublicUrlId == nil || *body.PublicUrlId != "public_url_1" || body.PublicUrlMutationRevision == nil ||
			*body.PublicUrlMutationRevision != 3 || body.PublishRunNumber == nil || *body.PublishRunNumber != 2 ||
			body.TeamId != "team_1" || body.DomainId != "domain_1" || body.CanonicalHostname != "api.example.test" ||
			body.Target != "http://127.0.0.1:3000" || !slices.Equal(body.AllowedIpPrefixes, []string{"192.0.2.0/24"}) {
			t.Fatalf("authorization request = %#v", body)
		}
	case <-time.After(time.Second):
		t.Fatal("authority received no authorization request")
	}
	if decision.IdentityID != "identity_1" || decision.PolicyRevision != 4 ||
		decision.CertificatePlan == nil || decision.CertificatePlan.ChallengeMethod != "dns-01" ||
		decision.RetrySecret != retrySecret {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestHostedAuthorizationRejectsMalformedCertificatePlans(t *testing.T) {
	request := authorization.Request{
		Operation: authorization.OperationPublishRunCreate, TeamID: "team_1", DomainID: "domain_1",
		CanonicalHostname: "api.example.test", PublicURLScope: "member", PublicURLMembershipID: "membership_1",
	}
	decision := authorization.Decision{
		IdentityID: "identity_1", TeamID: request.TeamID, ActingMembershipID: "membership_1",
		ActingRole: "owner", PolicyRevision: 1, DomainID: request.DomainID,
		CanonicalHostname: request.CanonicalHostname, PublicURLScope: request.PublicURLScope,
		PublicURLMembershipID: request.PublicURLMembershipID, DNSAuthorityReference: "dns_authority_1",
		CertificatePlan: &authorization.CertificatePlan{CacheKey: "example.test", Scope: "example.test",
			Identifiers: []string{"api.example.test"}, ChallengeMethod: "dns-01"},
	}
	if !validAuthorizationDecision(request, decision) {
		t.Fatal("valid certificate plan was rejected")
	}
	for _, test := range []struct {
		name   string
		mutate func(*authorization.CertificatePlan)
	}{
		{"too many names", func(p *authorization.CertificatePlan) {
			p.Identifiers = []string{"*.example.test", "api.example.test", "example.test"}
		}},
		{"duplicate", func(p *authorization.CertificatePlan) {
			p.Identifiers = []string{"api.example.test", "api.example.test"}
		}},
		{"unsorted", func(p *authorization.CertificatePlan) { p.Identifiers = []string{"example.test", "*.example.test"} }},
		{"not canonical", func(p *authorization.CertificatePlan) { p.Identifiers = []string{"API.EXAMPLE.TEST"} }},
		{"wrong hostname", func(p *authorization.CertificatePlan) { p.Identifiers = []string{"other.example.test"} }},
		{"invalid wildcard method", func(p *authorization.CertificatePlan) {
			p.Identifiers = []string{"*.example.test"}
			p.ChallengeMethod = "tls-alpn-01"
		}},
		{"unbounded cache key", func(p *authorization.CertificatePlan) { p.CacheKey = strings.Repeat("x", 257) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := decision
			plan := *decision.CertificatePlan
			test.mutate(&plan)
			candidate.CertificatePlan = &plan
			if validAuthorizationDecision(request, candidate) {
				t.Fatal("accepted an invalid authority certificate plan")
			}
		})
	}
}

func TestHostedAuthorizerUsesCurrentAuthorityMembershipsForRouteReads(t *testing.T) {
	received := make(chan [3]string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		received <- [3]string{request.Method, request.URL.Path, request.Header.Get("Authorization")}
		writeJSON(response, http.StatusOK, authorityv1.IdentityContext{
			Identity:       authorityv1.Identity{Id: "identity_1", DisplayName: "User"},
			Memberships:    []authorityv1.Membership{{Id: "membership_1", TeamId: "team_1"}},
			PersonalTeamId: "team_1",
		})
	}))
	defer server.Close()
	client, err := authorityclient.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := (hostedAuthorizer{client: client}).AuthorizePublicURLReads(t.Context(), "opaque-user-token")
	if err != nil {
		t.Fatal(err)
	}
	if principal.identityID != "identity_1" {
		t.Fatalf("principal = %#v", principal)
	}
	if _, ok := principal.teamIDs["team_1"]; !ok {
		t.Fatalf("principal = %#v", principal)
	}
	select {
	case got := <-received:
		if got != [3]string{http.MethodGet, "/v1/identity", "Bearer opaque-user-token"} {
			t.Fatalf("identity request = %v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("authority received no identity request")
	}
}

func TestLocalAuthorizerUsesCurrentMembershipAndDomain(t *testing.T) {
	retrySecret := [32]byte{4, 5, 6}
	store := localAuthorizationStoreStub{
		principal: controlstate.ControlPrincipal{IdentityID: "identity_1", RetrySecret: retrySecret},
		identity: controlstate.IdentityContext{Memberships: []controlstate.Membership{{
			ID: "membership_1", TeamID: "team_1", Role: "owner", PolicyRevision: 7,
		}}},
		domains: []controlstate.Domain{{
			ID: "domain_1", State: "ready", DNSAuthorityReference: "dns_authority_1",
		}},
	}
	decision, err := (localAuthorizer{store: store, sourceRevision: 9}).Authorize(t.Context(), authorization.Request{
		AccessToken: "access", Operation: authorization.OperationPublicURLCreate, TeamID: "team_1",
		PublicURLMembershipID: "membership_1", DomainID: "domain_1", CanonicalHostname: "api.example.test",
		PublicURLScope: "member", Target: "http://127.0.0.1:3000",
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.IdentityID != "identity_1" || decision.ActingMembershipID != "membership_1" ||
		decision.PolicyRevision != 7 || decision.RetrySecret != retrySecret {
		t.Fatalf("decision = %#v", decision)
	}
	store.authenticationError = controlstate.ErrControlAuthentication
	if _, err := (localAuthorizer{store: store}).Authorize(t.Context(), authorization.Request{}); !errors.Is(err, authorization.ErrUnauthenticated) {
		t.Fatalf("authentication error = %v", err)
	}
	databaseFailure := errors.New("database unavailable")
	store.authenticationError = databaseFailure
	if _, err := (localAuthorizer{store: store}).Authorize(t.Context(), authorization.Request{}); !errors.Is(err, authorization.ErrUnavailable) || !errors.Is(err, databaseFailure) {
		t.Fatalf("authentication store error = %v", err)
	}
}

func TestLocalAuthorizerAllowsAdministratorsToDeleteMemberPublicURLs(t *testing.T) {
	store := localAuthorizationStoreStub{
		principal: controlstate.ControlPrincipal{IdentityID: "identity_admin"},
		identity: controlstate.IdentityContext{Memberships: []controlstate.Membership{{
			ID: "membership_admin", TeamID: "team_1", Role: "admin", PolicyRevision: 7,
		}}},
		domains: []controlstate.Domain{{ID: "domain_1", State: "ready"}},
	}
	request := authorization.Request{
		AccessToken: "access", TeamID: "team_1", PublicURLMembershipID: "membership_owner",
		DomainID: "domain_1", CanonicalHostname: "api.example.test", PublicURLScope: "member",
		Target: "http://127.0.0.1:3000",
	}
	request.Operation = authorization.OperationPublicURLDelete
	decision, err := (localAuthorizer{store: store}).Authorize(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if decision.ActingMembershipID != "membership_admin" || decision.PublicURLMembershipID != "membership_owner" {
		t.Fatalf("decision = %#v", decision)
	}
	request.Operation = authorization.OperationPublicURLUpdate
	if _, err := (localAuthorizer{store: store}).Authorize(t.Context(), request); !errors.Is(err, authorization.ErrForbidden) {
		t.Fatalf("route update error = %v", err)
	}
}

func TestLocalAuthorizerAllowsRouteDeletionWhileDomainReleases(t *testing.T) {
	store := localAuthorizationStoreStub{
		principal: controlstate.ControlPrincipal{IdentityID: "identity_owner"},
		identity: controlstate.IdentityContext{Memberships: []controlstate.Membership{{
			ID: "membership_owner", TeamID: "team_1", Role: "owner", PolicyRevision: 8,
		}}},
		domains: []controlstate.Domain{{
			ID: "domain_1", State: "releasing", DNSAuthorityReference: "dns_authority_1",
		}},
	}
	request := authorization.Request{
		AccessToken: "access", TeamID: "team_1", PublicURLMembershipID: "membership_owner",
		DomainID: "domain_1", CanonicalHostname: "api.example.test", PublicURLScope: "member",
		Target: "http://127.0.0.1:3000",
	}
	request.Operation = authorization.OperationPublicURLDelete
	if _, err := (localAuthorizer{store: store}).Authorize(t.Context(), request); err != nil {
		t.Fatalf("route delete error = %v", err)
	}
	for _, operation := range []authorization.Operation{
		authorization.OperationPublicURLCreate,
		authorization.OperationPublicURLUpdate,
		authorization.OperationPublishRunCreate,
	} {
		request.Operation = operation
		if _, err := (localAuthorizer{store: store}).Authorize(t.Context(), request); !errors.Is(err, authorization.ErrForbidden) {
			t.Fatalf("%s error = %v", operation, err)
		}
	}
}

type externalPrincipalStoreStub struct{ secret [32]byte }

func (s externalPrincipalStoreStub) EnsureExternalAuthorityPrincipal(context.Context, string, time.Time) ([32]byte, error) {
	return s.secret, nil
}

type localAuthorizationStoreStub struct {
	principal           controlstate.ControlPrincipal
	identity            controlstate.IdentityContext
	domains             []controlstate.Domain
	authenticationError error
}

func (s localAuthorizationStoreStub) AuthenticateAccessToken(
	context.Context,
	credentials.AccessToken,
	int64,
	time.Time,
) (controlstate.ControlPrincipal, error) {
	return s.principal, s.authenticationError
}

func (s localAuthorizationStoreStub) IdentityContext(context.Context, string) (controlstate.IdentityContext, error) {
	return s.identity, nil
}

func (s localAuthorizationStoreStub) ListTeamDomains(context.Context, string, string) ([]controlstate.Domain, error) {
	return s.domains, nil
}

func pointer[T any](value T) *T { return &value }
