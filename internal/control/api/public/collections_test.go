package public

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestCollectionManagementRequiresExplicitCapabilityAndOrigin(t *testing.T) {
	database := &controlstate.Database{}
	for _, setup := range []struct {
		name   string
		config Config
		stores Stores
	}{
		{"missing store", Config{ControlURL: "https://control.example.test"}, Stores{}},
		{"environment store does not enable collections", Config{ControlURL: "https://control.example.test"}, Stores{Environments: database}},
		{"missing origin", Config{}, Stores{Collections: database}},
	} {
		t.Run(setup.name, func(t *testing.T) {
			handler, err := NewHandler(setup.config, setup.stores, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, route := range []struct{ method, path string }{
				{http.MethodPost, "/v1/projects/accounts/collections"},
				{http.MethodGet, "/v1/projects/accounts/collections?team_id=team"},
				{http.MethodGet, "/v1/projects/accounts/collections/coll_AAAAAAAAAAAAAAAAAAAAAA?team_id=team"},
				{http.MethodPut, "/v1/projects/accounts/collections/coll_AAAAAAAAAAAAAAAAAAAAAA/default"},
			} {
				request := httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`))
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				assertEnvironmentHTTPProblem(t, response.Code, response.Body.Bytes(), http.StatusServiceUnavailable, controlv1.Unavailable)
				if response.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("unavailable collection capability response may be cached")
				}
			}
		})
	}
	if stores := DatabaseStores(database); stores.Collections != database || stores.Environments != database {
		t.Fatal("database composition did not explicitly bind both capabilities")
	}
	if DatabaseStores(nil).Collections != nil {
		t.Fatal("nil database enabled collections")
	}
	handler, err := NewHandler(Config{ControlURL: "https://control.example.test"}, Stores{Collections: database}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/projects/accounts/environments", strings.NewReader(`{}`)))
	assertEnvironmentHTTPProblem(t, response.Code, response.Body.Bytes(), http.StatusServiceUnavailable, controlv1.Unavailable)
}

func TestCollectionResponseUsesConfiguredOriginAndCanonicalFields(t *testing.T) {
	h := handler{config: Config{ControlURL: "https://configured.example.test"}}
	input := controlstate.Collection{ID: "coll_AAAAAAAAAAAAAAAAAAAAAA", TeamID: "team", ProjectKey: "accounts", Name: "Customer previews", DefaultDefinitionRevision: 3, MutationRevision: 2}
	response := h.collectionResponse(input)
	if response.CollectionId != input.ID || response.Ref.Server != h.config.ControlURL || response.Ref.CollectionId != input.ID || response.Ref.ProjectKey != input.ProjectKey {
		t.Fatal("collection reference did not preserve its configured origin and scope", response)
	}
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || len(fields) != 7 || fields["collection_id"] == nil || fields["mutation_revision"] == nil {
		t.Fatal("collection response changed its closed public shape", string(data), err)
	}
	for _, collection := range []string{"", input.ID} {
		environment := h.environmentResponse(controlstate.Environment{ID: "env_AAAAAAAAAAAAAAAAAAAAAA", CollectionID: collection, ProjectKey: "accounts"})
		encoded, err := json.Marshal(environment)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), `"collection_id":null`) || strings.Contains(string(encoded), `"collection_id"`) != (collection != "") || environment.Ref.EnvironmentId != environment.Id {
			t.Fatal("environment membership encoding changed existing identity or emitted null", string(encoded))
		}
	}
}

func TestCollectionProblemsUseExistingSanitizedCodes(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
		code   controlv1.ProblemCode
	}{
		{controlstate.ErrCollectionInvalid, 400, controlv1.InvalidRequest},
		{controlstate.ErrCollectionStale, 409, controlv1.Conflict},
		{controlstate.ErrCollectionNotFound, 404, controlv1.NotFound},
		{controlstate.ErrServiceConflict, 409, controlv1.Conflict},
		{controlstate.ErrServiceAccess, 403, controlv1.Forbidden},
	} {
		response := httptest.NewRecorder()
		collectionProblem(t.Context(), response, "test collection", errors.Join(test.err, errors.New("sensitive-marker")))
		assertEnvironmentHTTPProblem(t, response.Code, response.Body.Bytes(), test.status, test.code)
		if strings.Contains(response.Body.String(), "sensitive-marker") {
			t.Fatal("collection problem disclosed backend data")
		}
		if errors.Is(test.err, controlstate.ErrCollectionInvalid) || errors.Is(test.err, controlstate.ErrCollectionStale) || errors.Is(test.err, controlstate.ErrCollectionNotFound) {
			response = httptest.NewRecorder()
			environmentProblem(t.Context(), response, "test environment collection selection", test.err)
			assertEnvironmentHTTPProblem(t, response.Code, response.Body.Bytes(), test.status, test.code)
		}
	}
}

func TestCollectionParameterErrorsCannotBeCached(t *testing.T) {
	handler, err := NewHandler(Config{ControlURL: "https://control.example.test"}, Stores{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/projects/accounts/collections", "/v1/projects/accounts/collections/coll_AAAAAAAAAAAAAAAAAAAAAA"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		assertEnvironmentHTTPProblem(t, response.Code, response.Body.Bytes(), 400, controlv1.InvalidRequest)
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("generated query binding error may be cached")
		}
	}
}
