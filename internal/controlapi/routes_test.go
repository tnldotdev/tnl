package controlapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
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
	authorizer := &recordingAuthorizer{principal: testRouteReadPrincipal()}
	h := &handler{store: store, authorizer: authorizer}
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
	if !slices.Equal(authorizer.readTokens, []string{"access-token"}) || len(authorizer.requests) != 0 {
		t.Fatalf("authorization = %#v", authorizer)
	}
}

func TestGetRouteDoesNotRevealRoutesOutsideCurrentTeams(t *testing.T) {
	store := &routeMutationStoreStub{route: controlstate.Route{ID: "route_1", TeamID: "team_other"}}
	h := &handler{store: store, authorizer: &recordingAuthorizer{principal: testRouteReadPrincipal()}}
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
	authorizer := &recordingAuthorizer{principal: testRouteReadPrincipal(), decision: authorization.Decision{
		IdentityID: "identity_1", TeamID: "team_1", ActingMembershipID: "membership_1",
		ActingRole: "owner", RouteMembershipID: "membership_1", TeamPolicyRevision: 7,
		DomainID: "domain_1", CanonicalHostname: "demo.example", RouteScope: "member",
	}}
	h := &handler{store: store, authorizer: authorizer}
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
	if len(authorizer.requests) != 1 || !slices.Equal(authorizer.readTokens, []string{"access-token"}) || !slices.Equal(store.authorizationRouteIDs, []string{"route_1"}) {
		t.Fatalf("authorization calls = %#v; route lookups = %v", authorizer, store.authorizationRouteIDs)
	}
	authorized := authorizer.requests[0]
	if authorized.AccessToken != "access-token" || authorized.Operation != authorization.OperationRouteUpdate || authorized.RouteID != store.route.ID ||
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
	for _, test := range []struct{ name, body string }{
		{"missing IP policy", `{"target":"http://127.0.0.1:4000"}`},
		{"missing target", `{"allowed_ip_prefixes":[]}`},
		{"null IP policy", `{"target":"http://127.0.0.1:4000","allowed_ip_prefixes":null}`},
		{"invalid target", `{"target":"https://127.0.0.1:4000","allowed_ip_prefixes":[]}`},
		{"duplicate canonical prefix", `{"target":"http://127.0.0.1:4000","allowed_ip_prefixes":["192.0.2.1/24","192.0.2.0/24"]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &routeMutationStoreStub{}
			h := &handler{store: store}
			request := httptest.NewRequest(http.MethodPatch, "/v1/routes/route_1", strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer access-token")
			response := httptest.NewRecorder()
			h.UpdateRoute(response, request, "route_1")
			if response.Code != http.StatusBadRequest || store.authorizationReads != 0 {
				t.Fatalf("response = %d, authorization reads = %d", response.Code, store.authorizationReads)
			}
		})
	}
}

func TestRouteMutationsRequireBearerSyntaxBeforeLookup(t *testing.T) {
	for _, test := range routeMutationCalls() {
		t.Run(test.name, func(t *testing.T) {
			store := &routeMutationStoreStub{}
			h := &handler{store: store}
			request := httptest.NewRequest(http.MethodPost, "/v1/routes/route_1", strings.NewReader(`{}`))
			response := httptest.NewRecorder()
			test.call(h, response, request)
			if response.Code != http.StatusUnauthorized || store.authorizationReads != 0 {
				t.Fatalf("response = %d, authorization reads = %d", response.Code, store.authorizationReads)
			}
		})
	}
}

func TestRouteMutationsAuthenticateBeforeLookup(t *testing.T) {
	for _, test := range routeMutationCalls() {
		t.Run(test.name, func(t *testing.T) {
			store := &routeMutationStoreStub{}
			authorizer := &recordingAuthorizer{readErr: authorization.ErrUnauthenticated}
			h := &handler{store: store, authorizer: authorizer}
			request := httptest.NewRequest(http.MethodPatch, "/v1/routes/route_1", strings.NewReader(`{
			"target":"http://127.0.0.1:4000",
			"allowed_ip_prefixes":[]
		}`))
			request.Header.Set("Authorization", "Bearer invalid-access-token")
			response := httptest.NewRecorder()
			test.call(h, response, request)
			if response.Code != http.StatusUnauthorized || store.authorizationReads != 0 || len(authorizer.requests) != 0 || !slices.Equal(authorizer.readTokens, []string{"invalid-access-token"}) {
				t.Fatalf("response = %d, authorization reads = %d", response.Code, store.authorizationReads)
			}
		})
	}
}

func TestRouteMutationsDoNotRevealRoutesOutsideCurrentTeams(t *testing.T) {
	store := &routeMutationStoreStub{route: controlstate.Route{
		ID: "route_1", TeamID: "team_other", DomainID: "domain_1", MembershipID: "membership_1",
		CanonicalHostname: "demo.example", Target: "http://127.0.0.1:3000",
		RouteScope: controlstate.RouteScopeMember, MutationRevision: 1,
	}}
	authorizer := &recordingAuthorizer{principal: testRouteReadPrincipal()}
	h := &handler{store: store, authorizer: authorizer}
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
	if len(authorizer.requests) != 0 {
		t.Fatalf("mutation authorizations = %v", authorizer.requests)
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
			RouteVersion: 7, PolicyRevision: 9, RouteSessionToken: credentials.RouteSessionToken("session-token"),
			State: controlstate.RouteSessionStarting,
		},
	}
	authorizer := &recordingAuthorizer{principal: testRouteReadPrincipal(), decision: authorization.Decision{
		IdentityID: "identity_1", TeamID: "team_1", ActingMembershipID: "membership_1",
		ActingRole: "member", RouteMembershipID: "membership_1", TeamPolicyRevision: 9,
		DomainID: "domain_1", CanonicalHostname: "demo.example", RouteScope: "member", RetrySecret: [32]byte{1, 2, 3},
		CertificatePlan: &authorization.CertificatePlan{
			CacheKey: "member.example", Scope: "member.example", Identifiers: []string{"member.example", "*.member.example"},
			ChallengeMethod: string(controlv1.Dns01),
		},
	}}
	h := &handler{config: Config{DNSAutomation: true}, store: store, authorizer: authorizer}
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
	if len(authorizer.requests) != 1 || authorizer.requests[0].AccessToken != "access-token" ||
		authorizer.requests[0].Operation != authorization.OperationRouteSessionCreate || authorizer.requests[0].RouteID != "route_1" ||
		authorizer.requests[0].RouteVersion != 7 || authorizer.requests[0].RouteMutationRevision != 4 ||
		store.sessionLookup != [2]string{"route_1", "session-idempotency"} || store.sessionRequest.IdempotencyKey != "session-idempotency" ||
		store.sessionRequest.ExpectedMutationRevision != 4 || store.sessionRequest.ActingIdentityID != "identity_1" ||
		store.sessionRequest.PolicyRevision != 9 || !reflect.DeepEqual(store.sessionRequest.RetrySecret, authorizer.decision.RetrySecret[:]) ||
		store.sessionRequest.RequestDigest == ([32]byte{}) {
		t.Fatalf("session authorization = %#v, store = %#v", authorizer, store)
	}
}

func TestCreateRouteSessionRejectsUnconfiguredDNSPlan(t *testing.T) {
	store := &routeMutationStoreStub{route: controlstate.Route{ID: "route_1", TeamID: "team_1"}}
	h := &handler{store: store, authorizer: &recordingAuthorizer{principal: testRouteReadPrincipal(), decision: authorization.Decision{CertificatePlan: &authorization.CertificatePlan{ChallengeMethod: "dns-01"}}}}
	request := httptest.NewRequest(http.MethodPost, "/v1/routes/route_1/sessions", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	h.CreateRouteSession(response, request, "route_1", controlv1.CreateRouteSessionParams{})
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "requires DNS-01 automation") {
		t.Fatalf("unsupported plan = %d: %s", response.Code, response.Body.String())
	}
}

func testRouteReadPrincipal() routeReadPrincipal {
	return routeReadPrincipal{identityID: "identity_1", teamIDs: map[string]struct{}{"team_1": {}}}
}

type routeMutationStoreStub struct {
	Store
	route                      controlstate.Route
	postSessionRoute           *controlstate.Route
	sessionSetup               controlstate.RouteSessionSetup
	update                     controlstate.AuthorizedRouteUpdateRequest
	authorizationReads         int
	page                       controlstate.RoutePage
	listTeamID                 string
	listCursor                 string
	authorizationRouteIDs      []string
	sessionLookup              [2]string
	sessionRequest             controlstate.RouteSessionRequest
	updates, sessions, deletes int
}

func (s *routeMutationStoreStub) ListAuthorizedRoutes(
	_ context.Context,
	teamID, cursor string,
) (controlstate.RoutePage, error) {
	s.listTeamID, s.listCursor = teamID, cursor
	return s.page, nil
}

func (s *routeMutationStoreStub) GetRouteForAuthorization(_ context.Context, routeID string) (controlstate.Route, error) {
	s.authorizationReads++
	s.authorizationRouteIDs = append(s.authorizationRouteIDs, routeID)
	if s.postSessionRoute != nil {
		return *s.postSessionRoute, nil
	}
	return s.route, nil
}

func (s *routeMutationStoreStub) GetRouteForSessionAuthorization(_ context.Context, routeID, key string) (controlstate.Route, error) {
	s.authorizationReads++
	s.sessionLookup = [2]string{routeID, key}
	return s.route, nil
}

func (s *routeMutationStoreStub) CreateRouteSession(
	_ context.Context,
	request controlstate.RouteSessionRequest,
	_ time.Time,
	_ time.Duration,
	_ time.Duration,
) (controlstate.RouteSessionSetup, error) {
	s.sessions++
	s.sessionRequest = request
	return s.sessionSetup, nil
}

func (s *routeMutationStoreStub) UpdateAuthorizedRoute(
	_ context.Context,
	request controlstate.AuthorizedRouteUpdateRequest,
	now time.Time,
) (controlstate.Route, error) {
	s.update = request
	s.updates++
	s.route.Target = request.Target
	s.route.PolicyRevision = int64(request.PolicyRevision)
	s.route.AllowedIPPrefixes = make([]netip.Prefix, len(request.AllowedIPPrefixes))
	for index, value := range request.AllowedIPPrefixes {
		s.route.AllowedIPPrefixes[index] = netip.MustParsePrefix(value)
	}
	s.route.UpdatedAt = now
	return s.route, nil
}

func (s *routeMutationStoreStub) DeleteAuthorizedRoute(context.Context, controlstate.AuthorizedRouteDeleteRequest, time.Time) error {
	s.deletes++
	return nil
}

type recordingAuthorizer struct {
	principal            routeReadPrincipal
	decision             authorization.Decision
	readErr, mutationErr error
	readTokens           []string
	requests             []authorization.Request
}

func (a *recordingAuthorizer) Authorize(_ context.Context, request authorization.Request) (authorization.Decision, error) {
	a.requests = append(a.requests, request)
	return a.decision, a.mutationErr
}

func (a *recordingAuthorizer) AuthorizeRouteReads(_ context.Context, token string) (routeReadPrincipal, error) {
	a.readTokens = append(a.readTokens, token)
	return a.principal, a.readErr
}

type routeMutationCall struct {
	name string
	call func(*handler, http.ResponseWriter, *http.Request)
}

func routeMutationCalls() []routeMutationCall {
	return []routeMutationCall{
		{"update", func(h *handler, w http.ResponseWriter, r *http.Request) { h.UpdateRoute(w, r, "route_1") }},
		{"delete", func(h *handler, w http.ResponseWriter, r *http.Request) { h.DeleteRoute(w, r, "route_1") }},
		{"session", func(h *handler, w http.ResponseWriter, r *http.Request) {
			h.CreateRouteSession(w, r, "route_1", controlv1.CreateRouteSessionParams{})
		}},
	}
}

func TestRouteMutationRejectionDoesNotReachStore(t *testing.T) {
	for _, test := range routeMutationCalls() {
		t.Run(test.name, func(t *testing.T) {
			store := &routeMutationStoreStub{route: controlstate.Route{ID: "route_1", TeamID: "team_1", MutationRevision: 7}}
			authorizer := &recordingAuthorizer{principal: testRouteReadPrincipal(), mutationErr: authorization.ErrForbidden}
			h := &handler{store: store, authorizer: authorizer}
			request := httptest.NewRequest(http.MethodPost, "/v1/routes/route_1", strings.NewReader(`{"target":"http://127.0.0.1:4000","allowed_ip_prefixes":[]}`))
			request.Header.Set("Authorization", "Bearer exact-access-token")
			response := httptest.NewRecorder()
			test.call(h, response, request)
			if response.Code != http.StatusForbidden || len(authorizer.requests) != 1 || authorizer.requests[0].AccessToken != "exact-access-token" ||
				store.authorizationReads != 1 || store.updates != 0 || store.deletes != 0 || store.sessions != 0 {
				t.Fatalf("response = %d: %s, authorizer = %#v, store = %#v", response.Code, response.Body.String(), authorizer, store)
			}
		})
	}
}

func TestCreateRouteCanonicalEquivalenceAndIdempotency(t *testing.T) {
	store := &routeCreationStore{result: controlstate.Route{ID: "route_created", CanonicalHostname: "demo.example"}}
	authorizer := &recordingAuthorizer{decision: authorization.Decision{
		IdentityID: "identity_1", TeamID: "team_1", RouteMembershipID: "membership_1", DomainID: "domain_1",
		CanonicalHostname: "demo.example", RouteScope: "member", TeamPolicyRevision: 9, DNSAuthorityReference: "dns_authority_1",
	}}
	h := &handler{store: store, authorizer: authorizer, config: Config{DNSAutomation: true}}
	for _, test := range []struct{ name, prefixes, target string }{
		{"unmasked unordered prefixes", `["2001:db8::1/64","192.0.2.9/24"]`, "http://127.0.0.1:3000"},
		{"canonical prefixes", `["192.0.2.0/24","2001:db8::/64"]`, "http://127.0.0.1:3000"},
		{"changed target", `["192.0.2.0/24","2001:db8::/64"]`, "http://127.0.0.1:4000"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/routes", strings.NewReader(`{"team_id":"team_1","membership_id":"membership_1","domain_id":"domain_1","canonical_hostname":"demo.example","route_scope":"member","target":"`+test.target+`","allowed_ip_prefixes":`+test.prefixes+`,"ephemeral":true}`))
			request.Header.Set("Authorization", "Bearer exact-access-token")
			request.Header.Set("Idempotency-Key", "create-key")
			response := httptest.NewRecorder()
			h.CreateRoute(response, request, controlv1.CreateRouteParams{})
			if response.Code != http.StatusCreated {
				t.Fatalf("response = %d: %s", response.Code, response.Body.String())
			}
		})
	}
	if len(store.requests) != 3 || len(authorizer.requests) != 3 || len(authorizer.readTokens) != 0 {
		t.Fatalf("calls = %#v, %#v", store, authorizer)
	}
	want := controlstate.CreateRouteRequest{
		TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1", ActingIdentityID: "identity_1", IdempotencyKey: "create-key",
		CanonicalHostname: "demo.example", Target: "http://127.0.0.1:3000", RouteScope: controlstate.RouteScopeMember,
		AllowedIPPrefixes: []string{"192.0.2.0/24", "2001:db8::/64"}, DNSState: controlstate.RouteDNSPending,
		DNSAuthorityReference: "dns_authority_1", PolicyRevision: 9, Ephemeral: true,
	}
	got := store.requests[0]
	got.RequestDigest = [32]byte{}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(store.requests[0], store.requests[1]) ||
		store.requests[0].RequestDigest == ([32]byte{}) || store.requests[0].RequestDigest == store.requests[2].RequestDigest {
		t.Fatalf("canonical requests = %#v", store.requests)
	}
	for _, request := range authorizer.requests {
		if request.AccessToken != "exact-access-token" || request.Operation != authorization.OperationRouteCreate || !slices.Equal(request.AllowedIPPrefixes, want.AllowedIPPrefixes) {
			t.Fatalf("authorization = %#v", request)
		}
	}
}

type routeCreationStore struct {
	Store
	result   controlstate.Route
	requests []controlstate.CreateRouteRequest
}

func (s *routeCreationStore) CreateRoute(_ context.Context, request controlstate.CreateRouteRequest, _ time.Time) (controlstate.Route, error) {
	s.requests = append(s.requests, request)
	return s.result, nil
}
