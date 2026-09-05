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

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestHostedAuthorizerSendsServiceSecretAndReturnsControlDecision(t *testing.T) {
	const serviceSecret = "0123456789abcdef0123456789abcdef"
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/service/authorize" || request.Header.Get("Authorization") != "Bearer "+serviceSecret {
			t.Fatalf("request = %s %s, authorization %q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		var body authorityv1.ServiceAuthorizationRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.AccessToken != "opaque-user-token" || body.Operation != authorityv1.RouteSessionCreate ||
			body.RouteId == nil || *body.RouteId != "route_1" || !slices.Equal(body.AllowedIpPrefixes, []string{"192.0.2.0/24"}) {
			t.Fatalf("authorization request = %#v", body)
		}
		writeJSON(response, http.StatusOK, authorityv1.ServiceAuthorizationDecision{
			IdentityId: "identity_1", TeamId: "team_1", ActingMembershipId: "membership_1",
			ActingRole: authorityv1.TeamRoleOwner, RouteMembershipId: pointer("membership_1"), TeamPolicyRevision: 4,
			DomainId: "domain_1", CanonicalHostname: "api.example.test", RouteScope: authorityv1.RouteScopeMember,
			DnsAuthorityReference: "dns_authority_1", CertificatePlan: &authorityv1.CertificatePlan{
				CacheKey: "example.test", Scope: "example.test", Identifiers: []string{"example.test", "*.example.test"},
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
		AccessToken: "opaque-user-token", Operation: authorization.OperationRouteSessionCreate,
		TeamID: "team_1", RouteMembershipID: "membership_1", DomainID: "domain_1",
		CanonicalHostname: "api.example.test", RouteScope: "member", Target: "http://127.0.0.1:3000",
		AllowedIPPrefixes: []string{"192.0.2.0/24"}, RouteID: "route_1", RouteVersion: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.IdentityID != "identity_1" || decision.TeamPolicyRevision != 4 ||
		decision.CertificatePlan == nil || decision.CertificatePlan.ChallengeMethod != "dns-01" ||
		decision.RetrySecret != retrySecret {
		t.Fatalf("decision = %#v", decision)
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
		AccessToken: "access", Operation: authorization.OperationRouteCreate, TeamID: "team_1",
		RouteMembershipID: "membership_1", DomainID: "domain_1", CanonicalHostname: "api.example.test",
		RouteScope: "member", Target: "http://127.0.0.1:3000",
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.IdentityID != "identity_1" || decision.ActingMembershipID != "membership_1" ||
		decision.TeamPolicyRevision != 7 || decision.RetrySecret != retrySecret {
		t.Fatalf("decision = %#v", decision)
	}
	store.authenticationError = controlstate.ErrControlAuthentication
	if _, err := (localAuthorizer{store: store}).Authorize(t.Context(), authorization.Request{}); !errors.Is(err, authorization.ErrUnauthenticated) {
		t.Fatalf("authentication error = %v", err)
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
