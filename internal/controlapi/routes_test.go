package controlapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestListRoutesUsesCurrentRouteReadAuthorization(t *testing.T) {
	store := &routeMutationStoreStub{page: controlstate.RoutePage{Routes: []controlstate.Route{{
		ID: "route_1", TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
		CanonicalHostname: "demo.example", Target: "http://127.0.0.1:3000",
		RouteScope: controlstate.RouteScopeMember, LifecycleState: controlstate.RouteLifecycleEnabled,
	}}}}
	h := &handler{store: store, authorizer: authorizerFunc(func(context.Context, authorization.Request) (authorization.Decision, error) {
		return authorization.Decision{}, nil
	})}
	request := httptest.NewRequest(http.MethodGet, "/v1/routes?team_id=team_1&cursor=route_0", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	h.ListRoutes(response, request, controlv1.ListRoutesParams{})
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if store.listTeamID != "team_1" || store.listCursor != "route_0" {
		t.Fatalf("list team = %q, cursor = %q", store.listTeamID, store.listCursor)
	}
}

func TestGetRouteDoesNotRevealRoutesOutsideCurrentTeams(t *testing.T) {
	store := &routeMutationStoreStub{route: controlstate.Route{ID: "route_1", TeamID: "team_other"}}
	h := &handler{store: store, authorizer: authorizerFunc(func(context.Context, authorization.Request) (authorization.Decision, error) {
		return authorization.Decision{}, nil
	})}
	request := httptest.NewRequest(http.MethodGet, "/v1/routes/route_1", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	h.GetRoute(response, request, "route_1")
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), `"code":"not_found"`) {
		t.Fatalf("response = %d: %s", response.Code, response.Body.String())
	}
}

func TestUpdateRouteAuthorizesExactRouteAndCanonicalMutation(t *testing.T) {
	store := &routeMutationStoreStub{route: controlstate.Route{
		ID: "route_1", TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
		CanonicalHostname: "demo.example", Target: "http://127.0.0.1:3000", RouteScope: controlstate.RouteScopeMember,
		PolicyRevision: 3, LifecycleState: controlstate.RouteLifecycleEnabled,
		AllowedIPPrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, MutationRevision: 4,
		Ephemeral: true,
	}}
	var authorized authorization.Request
	h := &handler{store: store, authorizer: authorizerFunc(func(_ context.Context, request authorization.Request) (authorization.Decision, error) {
		authorized = request
		return authorization.Decision{
			IdentityID: "identity_1", TeamID: request.TeamID, ActingMembershipID: "membership_1",
			ActingRole: "owner", RouteMembershipID: request.RouteMembershipID, TeamPolicyRevision: 7,
			DomainID: request.DomainID, CanonicalHostname: request.CanonicalHostname, RouteScope: request.RouteScope,
		}, nil
	})}
	request := httptest.NewRequest(http.MethodPatch, "/v1/routes/route_1", strings.NewReader(`{
		"target":"http://127.0.0.1:4000",
		"allowed_ip_prefixes":["2001:db8::1/64","192.0.2.9/24"]
	}`))
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	h.UpdateRoute(response, request, "route_1")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	wantPrefixes := []string{"192.0.2.0/24", "2001:db8::/64"}
	if authorized.Operation != authorization.OperationRouteUpdate || authorized.RouteID != store.route.ID ||
		authorized.TeamID != store.route.TeamID || authorized.DomainID != store.route.DomainID ||
		authorized.RouteMembershipID != store.route.MembershipID || authorized.CanonicalHostname != store.route.CanonicalHostname ||
		authorized.RouteScope != string(store.route.RouteScope) || !authorized.Ephemeral ||
		authorized.RouteMutationRevision != store.route.MutationRevision ||
		authorized.Target != "http://127.0.0.1:4000" || !slices.Equal(authorized.AllowedIPPrefixes, wantPrefixes) {
		t.Fatalf("authorization request = %#v", authorized)
	}
	if store.update.RouteID != store.route.ID || store.update.TeamID != store.route.TeamID ||
		store.update.ActingIdentityID != "identity_1" || store.update.PolicyRevision != 7 ||
		store.update.ExpectedMutationRevision != store.route.MutationRevision ||
		store.update.Target != authorized.Target || !slices.Equal(store.update.AllowedIPPrefixes, wantPrefixes) {
		t.Fatalf("stored update = %#v", store.update)
	}
}

func TestUpdateRouteRequiresCompleteDesiredState(t *testing.T) {
	for _, body := range []string{
		`{"target":"http://127.0.0.1:4000"}`,
		`{"allowed_ip_prefixes":[]}`,
		`{"target":"http://127.0.0.1:4000","allowed_ip_prefixes":null}`,
		`{"target":"https://127.0.0.1:4000","allowed_ip_prefixes":[]}`,
		`{"target":"http://127.0.0.1:4000","allowed_ip_prefixes":["192.0.2.1/24","192.0.2.0/24"]}`,
	} {
		store := &routeMutationStoreStub{}
		h := &handler{store: store}
		request := httptest.NewRequest(http.MethodPatch, "/v1/routes/route_1", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer access-token")
		response := httptest.NewRecorder()
		h.UpdateRoute(response, request, "route_1")
		if response.Code != http.StatusBadRequest || store.authorizationReads != 0 {
			t.Fatalf("body %s: response = %d, authorization reads = %d", body, response.Code, store.authorizationReads)
		}
	}
}

func TestRouteMutationsRequireBearerSyntaxBeforeLookup(t *testing.T) {
	for _, call := range []func(*handler, http.ResponseWriter, *http.Request){
		func(h *handler, response http.ResponseWriter, request *http.Request) {
			h.UpdateRoute(response, request, "route_1")
		},
		func(h *handler, response http.ResponseWriter, request *http.Request) {
			h.DeleteRoute(response, request, "route_1")
		},
		func(h *handler, response http.ResponseWriter, request *http.Request) {
			h.CreateRouteSession(response, request, "route_1", controlv1.CreateRouteSessionParams{})
		},
	} {
		store := &routeMutationStoreStub{}
		h := &handler{store: store}
		request := httptest.NewRequest(http.MethodPost, "/v1/routes/route_1", strings.NewReader(`{}`))
		response := httptest.NewRecorder()
		call(h, response, request)
		if response.Code != http.StatusUnauthorized || store.authorizationReads != 0 {
			t.Fatalf("response = %d, authorization reads = %d", response.Code, store.authorizationReads)
		}
	}
}

func TestRouteMutationsAuthenticateBeforeLookup(t *testing.T) {
	for _, call := range []func(*handler, http.ResponseWriter, *http.Request){
		func(h *handler, response http.ResponseWriter, request *http.Request) {
			h.UpdateRoute(response, request, "route_1")
		},
		func(h *handler, response http.ResponseWriter, request *http.Request) {
			h.DeleteRoute(response, request, "route_1")
		},
		func(h *handler, response http.ResponseWriter, request *http.Request) {
			h.CreateRouteSession(response, request, "route_1", controlv1.CreateRouteSessionParams{})
		},
	} {
		store := &routeMutationStoreStub{}
		h := &handler{store: store, authorizer: routeReadErrorAuthorizer{err: authorization.ErrUnauthenticated}}
		request := httptest.NewRequest(http.MethodPatch, "/v1/routes/route_1", strings.NewReader(`{
			"target":"http://127.0.0.1:4000",
			"allowed_ip_prefixes":[]
		}`))
		request.Header.Set("Authorization", "Bearer invalid-access-token")
		response := httptest.NewRecorder()
		call(h, response, request)
		if response.Code != http.StatusUnauthorized || store.authorizationReads != 0 {
			t.Fatalf("response = %d, authorization reads = %d", response.Code, store.authorizationReads)
		}
	}
}

func TestRouteMutationsDoNotRevealRoutesOutsideCurrentTeams(t *testing.T) {
	store := &routeMutationStoreStub{route: controlstate.Route{
		ID: "route_1", TeamID: "team_other", DomainID: "domain_1", MembershipID: "membership_1",
		CanonicalHostname: "demo.example", Target: "http://127.0.0.1:3000",
		RouteScope: controlstate.RouteScopeMember, MutationRevision: 1,
	}}
	mutationCalls := 0
	h := &handler{store: store, authorizer: authorizerFunc(func(context.Context, authorization.Request) (authorization.Decision, error) {
		mutationCalls++
		return authorization.Decision{}, nil
	})}
	calls := []struct {
		method string
		body   string
		call   func(http.ResponseWriter, *http.Request)
	}{
		{http.MethodPatch, `{"target":"http://127.0.0.1:4000","allowed_ip_prefixes":[]}`, func(response http.ResponseWriter, request *http.Request) {
			h.UpdateRoute(response, request, "route_1")
		}},
		{http.MethodDelete, "", func(response http.ResponseWriter, request *http.Request) {
			h.DeleteRoute(response, request, "route_1")
		}},
		{http.MethodPost, "", func(response http.ResponseWriter, request *http.Request) {
			h.CreateRouteSession(response, request, "route_1", controlv1.CreateRouteSessionParams{})
		}},
	}
	for _, test := range calls {
		request := httptest.NewRequest(test.method, "/v1/routes/route_1", strings.NewReader(test.body))
		request.Header.Set("Authorization", "Bearer access-token")
		response := httptest.NewRecorder()
		test.call(response, request)
		if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), `"code":"not_found"`) {
			t.Fatalf("%s response = %d: %s", test.method, response.Code, response.Body.String())
		}
	}
	if mutationCalls != 0 {
		t.Fatalf("mutation authorizations = %d", mutationCalls)
	}
}

func TestUpdateRouteMapsOpenSessionConflict(t *testing.T) {
	response := httptest.NewRecorder()
	writeControlStateProblem(response, "update route", controlstate.ErrRouteAttached)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"code":"route_attached"`) {
		t.Fatalf("response = %d: %s", response.Code, response.Body.String())
	}
}

func TestCreateRouteSessionReturnsAuthoritativeRouteState(t *testing.T) {
	expiresAt := time.Date(2026, 9, 5, 12, 2, 0, 0, time.UTC)
	updatedAt := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	store := &routeMutationStoreStub{
		route: controlstate.Route{
			ID: "route_1", TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
			CanonicalHostname: "demo.example", Target: "http://127.0.0.1:3000",
			RouteScope: controlstate.RouteScopeMember, LifecycleState: controlstate.RouteLifecycleEnabled,
			MutationRevision: 4, AuthorizationRouteVersion: 7, Ephemeral: true,
		},
		postSessionRoute: &controlstate.Route{
			ID: "route_1", TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
			CanonicalHostname: "demo.example", Target: "http://127.0.0.1:3000",
			RouteScope: controlstate.RouteScopeMember, LifecycleState: controlstate.RouteLifecycleEnabled,
			NextRouteVersion: 8, MutationRevision: 5, Ephemeral: true, ExpiresAt: &expiresAt,
			AttachedSessionID: "session_1", UpdatedAt: updatedAt,
		},
		sessionSetup: controlstate.RouteSessionSetup{
			RouteSessionID: "session_1", RouteID: "route_1", TeamID: "team_1", MembershipID: "membership_1",
			RouteVersion: 7, PolicyRevision: 9, SessionToken: credentials.SessionToken("session-token"),
			State: controlstate.RouteSessionStarting,
		},
	}
	h := &handler{store: store, authorizer: authorizerFunc(func(_ context.Context, request authorization.Request) (authorization.Decision, error) {
		return authorization.Decision{
			IdentityID: "identity_1", TeamID: request.TeamID, ActingMembershipID: "membership_1",
			ActingRole: "member", RouteMembershipID: "membership_1", TeamPolicyRevision: 9,
			DomainID: request.DomainID, CanonicalHostname: request.CanonicalHostname, RouteScope: request.RouteScope,
			CertificatePlan: &authorization.CertificatePlan{
				CacheKey: "member.example", Scope: "member.example", Identifiers: []string{"member.example", "*.member.example"},
				ChallengeMethod: string(controlv1.Dns01),
			},
		}, nil
	})}
	request := httptest.NewRequest(http.MethodPost, "/v1/routes/route_1/sessions", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	request.Header.Set("Idempotency-Key", "session-idempotency")
	response := httptest.NewRecorder()
	h.CreateRouteSession(response, request, "route_1", controlv1.CreateRouteSessionParams{})
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	var setup controlv1.RouteSessionSetup
	if err := json.Unmarshal(response.Body.Bytes(), &setup); err != nil {
		t.Fatal(err)
	}
	if setup.Route.AttachedSessionId == nil || *setup.Route.AttachedSessionId != "session_1" ||
		setup.Route.ExpiresAt == nil || !setup.Route.ExpiresAt.Equal(expiresAt) || !setup.Route.UpdatedAt.Equal(updatedAt) ||
		setup.Route.NextRouteVersion != 8 || store.authorizationReads != 2 {
		t.Fatalf("route = %#v, authorization reads = %d", setup.Route, store.authorizationReads)
	}
}

type authorizerFunc func(context.Context, authorization.Request) (authorization.Decision, error)

func (f authorizerFunc) Authorize(ctx context.Context, request authorization.Request) (authorization.Decision, error) {
	return f(ctx, request)
}

func (f authorizerFunc) AuthorizeRouteReads(context.Context, string) (routeReadPrincipal, error) {
	return routeReadPrincipal{identityID: "identity_1", teamIDs: map[string]struct{}{"team_1": {}}}, nil
}

type routeReadErrorAuthorizer struct{ err error }

func (a routeReadErrorAuthorizer) Authorize(context.Context, authorization.Request) (authorization.Decision, error) {
	return authorization.Decision{}, a.err
}

func (a routeReadErrorAuthorizer) AuthorizeRouteReads(context.Context, string) (routeReadPrincipal, error) {
	return routeReadPrincipal{}, a.err
}

type routeMutationStoreStub struct {
	Store
	route              controlstate.Route
	postSessionRoute   *controlstate.Route
	sessionSetup       controlstate.RouteSessionSetup
	update             controlstate.AuthorizedRouteUpdateRequest
	authorizationReads int
	page               controlstate.RoutePage
	listTeamID         string
	listCursor         string
}

func (s *routeMutationStoreStub) ListAuthorizedRoutes(
	_ context.Context,
	teamID, cursor string,
) (controlstate.RoutePage, error) {
	s.listTeamID, s.listCursor = teamID, cursor
	return s.page, nil
}

func (s *routeMutationStoreStub) GetRouteForAuthorization(context.Context, string) (controlstate.Route, error) {
	s.authorizationReads++
	if s.postSessionRoute != nil {
		return *s.postSessionRoute, nil
	}
	return s.route, nil
}

func (s *routeMutationStoreStub) GetRouteForSessionAuthorization(context.Context, string, string) (controlstate.Route, error) {
	s.authorizationReads++
	return s.route, nil
}

func (s *routeMutationStoreStub) CreateRouteSession(
	context.Context,
	controlstate.RouteSessionRequest,
	time.Time,
	time.Duration,
	time.Duration,
) (controlstate.RouteSessionSetup, error) {
	return s.sessionSetup, nil
}

func (s *routeMutationStoreStub) UpdateAuthorizedRoute(
	_ context.Context,
	request controlstate.AuthorizedRouteUpdateRequest,
	now time.Time,
) (controlstate.Route, error) {
	s.update = request
	s.route.Target = request.Target
	s.route.PolicyRevision = int64(request.PolicyRevision)
	s.route.AllowedIPPrefixes = make([]netip.Prefix, len(request.AllowedIPPrefixes))
	for index, value := range request.AllowedIPPrefixes {
		s.route.AllowedIPPrefixes[index] = netip.MustParsePrefix(value)
	}
	s.route.UpdatedAt = now
	return s.route, nil
}
