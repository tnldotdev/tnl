package controlapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestHostnameLookupUsesCurrentTeamAuthorizationAndOneLookup(t *testing.T) {
	for _, test := range []struct {
		name, query           string
		readErr, lookupErr    error
		status, calls, routes int
	}{
		{name: "found", query: "team_id=team_1&canonical_hostname=demo.example", status: 200, calls: 1, routes: 1},
		{name: "missing", query: "team_id=team_1&canonical_hostname=demo.example", lookupErr: controlstate.ErrRouteNotFound, status: 200, calls: 1},
		{name: "unauthenticated", query: "team_id=team_1&canonical_hostname=demo.example", readErr: authorization.ErrUnauthenticated, status: 401},
		{name: "unauthorized team", query: "team_id=team_other&canonical_hostname=demo.example", status: 403},
		{name: "noncanonical", query: "team_id=team_1&canonical_hostname=Demo.Example", status: 400},
		{name: "empty filter", query: "team_id=team_1&canonical_hostname=", status: 400},
		{name: "duplicate filter", query: "team_id=team_1&canonical_hostname=demo.example&canonical_hostname=other.example", status: 400},
		{name: "cursor", query: "team_id=team_1&canonical_hostname=demo.example&cursor=route_0", status: 400},
		{name: "empty cursor", query: "team_id=team_1&canonical_hostname=demo.example&cursor=", status: 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &hostnameLookupStore{err: test.lookupErr}
			authorizer := &recordingAuthorizer{principal: testRouteReadPrincipal(), readErr: test.readErr}
			h := &handler{store: store, authorizer: authorizer}
			request := httptest.NewRequest(http.MethodGet, "/v1/routes?"+test.query, nil)
			request.Header.Set("Authorization", "Bearer current-token")
			response := httptest.NewRecorder()
			h.ListRoutes(response, request, controlv1.ListRoutesParams{})
			if response.Code != test.status || store.calls != test.calls || len(authorizer.readTokens) != 1 {
				t.Fatalf("status=%d body=%s lookups=%d authorization=%v", response.Code, response.Body.String(), store.calls, authorizer.readTokens)
			}
			if test.calls > 0 && store.lookup != [2]string{"team_1", "demo.example"} {
				t.Fatalf("lookup escaped its team/hostname: %v", store.lookup)
			}
			if test.status == http.StatusOK {
				var page controlv1.RoutePage
				if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
					t.Fatal(err)
				}
				if page.Routes == nil || len(page.Routes) != test.routes || page.NextCursor != nil {
					t.Fatalf("filtered response = %+v", page)
				}
			}
		})
	}
}

type hostnameLookupStore struct {
	Store  // Any attempt to use the unfiltered list path fails the test.
	err    error
	calls  int
	lookup [2]string
}

func (s *hostnameLookupStore) GetAuthorizedRouteByHostname(_ context.Context, teamID, hostname string) (controlstate.Route, error) {
	s.calls++
	s.lookup = [2]string{teamID, hostname}
	return controlstate.Route{ID: "route_found", TeamID: teamID, CanonicalHostname: hostname, LifecycleState: controlstate.RouteLifecycleEnabled}, s.err
}
