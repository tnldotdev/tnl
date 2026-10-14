package controlapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type visitorGrantStoreStub struct {
	created controlstate.CreateTeamURLShareGrantRequest
	grant   controlstate.VisitorShareGrant
}

func (s *visitorGrantStoreStub) CreateTeamURLShareGrant(_ context.Context, request controlstate.CreateTeamURLShareGrantRequest, now time.Time) (controlstate.VisitorShareGrant, error) {
	s.created = request
	s.grant = controlstate.VisitorShareGrant{
		ID: "shr_0123456789abcdefghijkl", TeamID: request.TeamID, PublicURLID: request.PublicURLID,
		Kind: "team_url", CreatedByIdentityID: request.ActingIdentityID, CreatedAt: now,
	}
	return s.grant, nil
}

func (s *visitorGrantStoreStub) GetTeamURLShareGrant(_ context.Context, _ string) (controlstate.VisitorShareGrant, error) {
	return s.grant, nil
}

func (s *visitorGrantStoreStub) ListTeamURLShareGrants(_ context.Context, _, _, _ string) (controlstate.VisitorShareGrantPage, error) {
	return controlstate.VisitorShareGrantPage{Shares: []controlstate.VisitorShareGrant{s.grant}}, nil
}

func (s *visitorGrantStoreStub) RevokeTeamURLShareGrant(_ context.Context, _, _, _ string, now time.Time) (controlstate.VisitorShareGrant, error) {
	s.grant.RevokedAt = &now
	return s.grant, nil
}

func TestExactTeamShareRequiresOwnerDecisionAndSupportedService(t *testing.T) {
	routes := &publicURLMutationStoreStub{route: controlstate.PublicURL{
		ID: "url_0123456789abcdefghijkl", TeamID: "team_1", DomainID: "dom_1", MembershipID: "mem_1",
		CanonicalHostname: "orders.example.test", ServiceProtocol: controlstate.PublicURLServicePostgres,
		Purpose: controlstate.PublicURLPurposeApp, PublicURLScope: controlstate.PublicURLScopeMember,
		LifecycleState: controlstate.PublicURLLifecycleEnabled, MutationRevision: 3,
	}}
	grants := &visitorGrantStoreStub{}
	authorizer := &recordingAuthorizer{principal: testPublicURLReadPrincipal(), decision: authorization.Decision{
		IdentityID: "identity_1", TeamID: "team_1", PolicyRevision: 7,
	}}
	h := &handler{store: routes, visitorGrants: grants, authorizer: authorizer, config: Config{BrowserOIDCClientID: "browser-client"}}
	create := func(team string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/v1/shares/grants", strings.NewReader(`{"team_id":"`+team+`","public_url_id":"url_0123456789abcdefghijkl"}`))
		request.Header.Set("Authorization", "Bearer access-token")
		request.Header.Set("Idempotency-Key", "create-team-share")
		response := httptest.NewRecorder()
		h.CreateShareGrant(response, request, controlv1.CreateShareGrantParams{})
		return response
	}
	if response := create("team_other"); response.Code != http.StatusNotFound || grants.created.PublicURLID != "" {
		t.Fatalf("another team's grant = %d %s", response.Code, response.Body.String())
	}
	routes.route.ServiceProtocol = controlstate.PublicURLServiceSSH
	if response := create("team_1"); response.Code != http.StatusBadRequest || grants.created.PublicURLID != "" {
		t.Fatalf("SSH share = %d %s", response.Code, response.Body.String())
	}
	routes.route.ServiceProtocol = controlstate.PublicURLServicePostgres
	response := create("team_1")
	if response.Code != http.StatusCreated || grants.created.PublicURLID != routes.route.ID ||
		grants.created.ActingIdentityID != "identity_1" || grants.created.ExpectedMutationRevision != routes.route.MutationRevision ||
		len(authorizer.requests) != 1 || authorizer.requests[0].Operation != authorization.OperationShareCreate {
		t.Fatalf("database share = %d %s, request=%+v, authorization=%+v", response.Code, response.Body.String(), grants.created, authorizer.requests)
	}
}
