package public

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func TestPortableCORSExactOperationAllowlist(t *testing.T) {
	h := testHandler(t, Config{}, nil, nil, nil)
	for _, operation := range []struct {
		method, path, headers string
	}{
		{"GET", "/v1/projects/shop/deployments", "authorization"},
		{"POST", "/v1/projects/shop/deployments", "authorization, content-type, idempotency-key"},
		{"GET", "/v1/projects/shop/deployments/staging", "authorization"},
		{"PATCH", "/v1/projects/shop/deployments/staging", "authorization, content-type, if-match"},
		{"DELETE", "/v1/projects/shop/deployments/staging", "authorization, if-match"},
		{"POST", "/v1/projects/shop/deployments/staging/publisher-enrollments", "authorization, content-type, idempotency-key"},
		{"GET", "/v1/projects/shop/deployments/staging/publishers", "authorization"},
		{"GET", "/v1/projects/shop/deployments/staging/publishers/pub_1234567890123456789012", "authorization"},
		{"DELETE", "/v1/projects/shop/deployments/staging/publishers/pub_1234567890123456789012", "authorization"},
		{"POST", "/v1/projects/shop/deployments/staging/services/db/select", "content-type"},
		{"POST", "/v1/visitor-tokens", "authorization, content-type"},
		{"POST", "/v1/services/svc_1234567890123456789012/connector-peer-pairs", "authorization, content-type"},
		{"POST", "/v1/services/svc_1234567890123456789012/connector-peer-pairs/cpp_1234567890123456789012/renew", "content-type"},
		{"POST", "/v1/services/svc_1234567890123456789012/connector-peer-pairs/cpp_1234567890123456789012/rebind", "content-type"},
		{"POST", "/v1/services/svc_1234567890123456789012/connector-peer-pairs/cpp_1234567890123456789012/retire", "content-type"},
	} {
		t.Run(operation.method+" "+operation.path, func(t *testing.T) {
			// no body, team query, or authentication: preflight must not decode
			// operation parameters or enter any authorization or mutation owner.
			r := httptest.NewRequest(http.MethodOptions, operation.path, nil)
			r.Header.Set("Origin", "https://arbitrary.example")
			r.Header.Set("Access-Control-Request-Method", operation.method)
			r.Header.Set("Access-Control-Request-Headers", operation.headers)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusNoContent || w.Body.Len() != 0 || w.Header().Get("Access-Control-Allow-Origin") != "*" ||
				w.Header().Get("Access-Control-Allow-Credentials") != "" || w.Header().Get("Access-Control-Allow-Methods") != operation.method {
				t.Fatal("portable operation preflight failed or enabled cookies", w.Code, w.Header(), w.Body.String())
			}
		})
	}
	for _, operation := range []struct {
		method, path, headers string
	}{
		{"PUT", "/v1/projects/shop/deployments/staging", "authorization, content-type"},
		{"GET", "/v1/projects/shop/deployments", "authorization, if-match"},
		{"POST", "/v1/projects/shop/deployment-credentials", "authorization, content-type"},
		{"POST", "/v1/projects/shop/deployments/staging/services", "authorization, content-type"},
		{"POST", "/v1/services/svc_1234567890123456789012/connector-peer-pairs/cpp_1234567890123456789012/retire", "authorization, content-type"},
		{"POST", "/v1/services/svc_1234567890123456789012/runs", "authorization, content-type"},
		{"POST", "/v1/services/svc_1234567890123456789012/runs/srun_1234567890123456789012/connector-peer-pairs/cpp_1234567890123456789012/delivery", "authorization, content-type"},
		{"POST", "/v1/guest-demo", "content-type"},
		{"POST", "/v1/browser/challenge/attempt", "content-type"},
		{"GET", "/v1/browser/service-login", ""},
		{"GET", "/v1/browser/callback", ""},
		{"GET", "/v1/admin/status", "authorization"},
		{"GET", "/v1/services", "authorization"},
		{"GET", "/v1/discovery", ""},
	} {
		t.Run("reject "+operation.method+" "+operation.path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodOptions, operation.path, nil)
			r.Header.Set("Origin", "https://arbitrary.example")
			r.Header.Set("Access-Control-Request-Method", operation.method)
			r.Header.Set("Access-Control-Request-Headers", operation.headers)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 || w.Header().Get("Access-Control-Allow-Origin") != "" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
				t.Fatal("unselected operation advertised browser access", w.Code, w.Header())
			}
		})
	}
}

type corsAuthorizationStore struct {
	AuthorizationStore
	tokens []string
}

func (s *corsAuthorizationStore) AuthenticateAccessToken(_ context.Context, token credentials.AccessToken, _ time.Time) (controlstate.ControlPrincipal, error) {
	s.tokens = append(s.tokens, string(token))
	if token != "explicit-access-token" {
		return controlstate.ControlPrincipal{}, controlstate.ErrControlAuthentication
	}
	return controlstate.ControlPrincipal{IdentityID: "identity_1", SessionID: "session_1"}, nil
}

func (*corsAuthorizationStore) IdentityContext(context.Context, string) (controlstate.IdentityContext, error) {
	return controlstate.IdentityContext{Memberships: []controlstate.Membership{{TeamID: "team_1"}}}, nil
}

func (*corsAuthorizationStore) AuthorizeTeamSession(context.Context, controlstate.ControlPrincipal, string, time.Time) error {
	return nil
}

type corsDeploymentStore struct {
	DeploymentStore
	requests []controlstate.CreateDeploymentRequest
	updates  []controlstate.UpdateDeploymentRequest
	err      error
}

func (s *corsDeploymentStore) CreateDeployment(_ context.Context, request controlstate.CreateDeploymentRequest) (controlstate.Deployment, error) {
	s.requests = append(s.requests, request)
	return controlstate.Deployment{ID: "dpl_1234567890123456789012", Revision: 7}, s.err
}

func (s *corsDeploymentStore) UpdateDeployment(_ context.Context, request controlstate.UpdateDeploymentRequest) (controlstate.Deployment, error) {
	s.updates = append(s.updates, request)
	return controlstate.Deployment{ID: "dpl_1234567890123456789012", Revision: 8}, s.err
}

type corsPublisherAccessStore struct {
	PublisherIdentityStore
	calls int
	scope controlstate.PublisherScope
	err   error
}

func (s *corsPublisherAccessStore) AuthenticatePublisherAccess(_ context.Context, token, source string, _ time.Time) (controlstate.PublisherIdentity, error) {
	s.calls++
	if token != "pta_explicit-deployment-token" || source != "192.0.2.1/32" {
		panic("CORS changed the explicit credential or trusted socket source")
	}
	return controlstate.PublisherIdentity{Scope: s.scope}, s.err
}

func TestPortableCORSRealDeploymentMutationRetainsAuthentication(t *testing.T) {
	for _, test := range []struct {
		name, authorization, team string
		publisherScope            controlstate.PublisherScope
		publisherErr, mutationErr error
		status, human, publisher  int
		mutations                 int
	}{
		{name: "cookie is not authentication", team: "team_1", status: 401},
		{name: "wrong scheme", authorization: "Basic explicit-access-token", team: "team_1", status: 401},
		{name: "invalid bearer", authorization: "Bearer rejected-token", team: "team_1", status: 401, human: 1},
		{name: "control bearer", authorization: "Bearer explicit-access-token", team: "team_1", status: 201, human: 1, mutations: 1},
		{name: "other team", authorization: "Bearer explicit-access-token", team: "team_other", status: 404, human: 1},
		{name: "deployment bearer", authorization: "Bearer pta_explicit-deployment-token", team: "team_1", publisherScope: controlstate.PublisherScope{Kind: controlstate.DeploymentCredentialGrant, TeamID: "team_1"}, status: 201, publisher: 1, mutations: 1},
		{name: "other deployment team", authorization: "Bearer pta_explicit-deployment-token", team: "team_1", publisherScope: controlstate.PublisherScope{Kind: controlstate.DeploymentCredentialGrant, TeamID: "team_other"}, status: 403, publisher: 1},
		{name: "service publisher is not manager", authorization: "Bearer pta_explicit-deployment-token", team: "team_1", publisherScope: controlstate.PublisherScope{Kind: "service", TeamID: "team_1"}, status: 403, publisher: 1},
		{name: "revoked deployment bearer", authorization: "Bearer pta_explicit-deployment-token", team: "team_1", publisherErr: controlstate.ErrPublisherIdentity, status: 401, publisher: 1},
		{name: "transaction denies management", authorization: "Bearer explicit-access-token", team: "team_1", mutationErr: controlstate.ErrDeploymentAccess, status: 403, human: 1, mutations: 1},
		{name: "internal failure is sanitized", authorization: "Bearer explicit-access-token", team: "team_1", mutationErr: errors.New("private-database-password"), status: 500, human: 1, mutations: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			authorization := &corsAuthorizationStore{}
			deployments := &corsDeploymentStore{err: test.mutationErr}
			publishers := &corsPublisherAccessStore{scope: test.publisherScope, err: test.publisherErr}
			h := testHandler(t, Config{}, nil, authorization, nil, Stores{Deployments: deployments, PublisherIdentities: publishers})
			path := "/v1/projects/shop/deployments?team_id=" + test.team
			preflight := httptest.NewRequest(http.MethodOptions, path, nil)
			preflight.Header.Set("Origin", "https://app.example")
			preflight.Header.Set("Access-Control-Request-Method", "POST")
			preflight.Header.Set("Access-Control-Request-Headers", "authorization, content-type, idempotency-key")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, preflight)
			if w.Code != 204 || len(authorization.tokens) != 0 || publishers.calls != 0 || len(deployments.requests) != 0 {
				t.Fatal("preflight authenticated or mutated state", w.Code)
			}
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"name":"staging","targets":{}}`))
			r.Header.Set("Origin", "https://app.example")
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Idempotency-Key", "exact-create")
			r.AddCookie(&http.Cookie{Name: "__Host-tnl-browser", Value: "ambient-cookie-secret"})
			if test.authorization != "" {
				r.Header.Set("Authorization", test.authorization)
			}
			w = httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.status || len(authorization.tokens) != test.human || publishers.calls != test.publisher || len(deployments.requests) != test.mutations ||
				w.Header().Get("Access-Control-Allow-Origin") != "*" || w.Header().Get("Access-Control-Allow-Credentials") != "" ||
				w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("CORS changed mutation authorization or cookie policy", w.Code, w.Header(), w.Body.String())
			}
			if test.status == 201 && (w.Header().Get("ETag") != `"7"` || w.Header().Get("Access-Control-Expose-Headers") != "ETag") {
				t.Fatal("browser cannot capture the deployment revision", w.Header())
			}
			for _, request := range deployments.requests {
				if request.TeamID != test.team || request.ProjectKey != "shop" || request.IdempotencyKey != "exact-create" ||
					test.publisher == 1 && (request.AccessToken != "pta_explicit-deployment-token" || request.ActorID != "") ||
					test.human == 1 && (request.ActorID != "identity_1" || request.AccessToken != "") {
					t.Fatal("CORS changed the authorized deployment scope")
				}
			}
			for _, secret := range []string{"ambient-cookie-secret", "explicit-access-token", "pta_explicit-deployment-token", "private-database-password"} {
				if strings.Contains(w.Body.String(), secret) {
					t.Fatal("response disclosed authentication or internal error details")
				}
			}
		})
	}
}

func TestPortableCORSConditionalUpdateKeepsRevisionFence(t *testing.T) {
	for _, test := range []struct {
		name, condition string
		err             error
		status, calls   int
	}{
		{"missing", "", nil, 428, 0},
		{"weak", `W/"7"`, nil, 400, 0},
		{"multiple", `"7", "8"`, nil, 400, 0},
		{"stale", `"7"`, controlstate.ErrDeploymentStale, 412, 1},
		{"current", `"7"`, nil, 200, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &corsDeploymentStore{err: test.err}
			h := testHandler(t, Config{}, nil, &corsAuthorizationStore{}, nil, Stores{Deployments: store})
			r := httptest.NewRequest(http.MethodPatch, "/v1/projects/shop/deployments/staging?team_id=team_1", strings.NewReader(`{"targets":{}}`))
			r.Header.Set("Origin", "https://app.example")
			r.Header.Set("Authorization", "Bearer explicit-access-token")
			r.Header.Set("Content-Type", "application/json")
			if test.condition != "" {
				r.Header.Set("If-Match", test.condition)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.status || len(store.updates) != test.calls || w.Header().Get("Access-Control-Allow-Origin") != "*" ||
				w.Header().Get("Access-Control-Expose-Headers") != "ETag" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
				t.Fatal("browser update lost its revision fence", w.Code, w.Header())
			}
			for _, update := range store.updates {
				if update.ExpectedRevision != 7 || update.TeamID != "team_1" || update.ProjectKey != "shop" ||
					update.ActorID != "identity_1" || update.Selector != "staging" {
					t.Fatal("browser update changed its authenticated scope or revision")
				}
			}
			if test.status == 200 && w.Header().Get("ETag") != `"8"` {
				t.Fatal("browser update did not return its next revision")
			}
		})
	}
}

type corsDeploymentConnectStore struct {
	calls  int
	source controlstate.VisitorTokenSource
	err    error
}

func (s *corsDeploymentConnectStore) SelectDeploymentServiceRun(_ context.Context, team, project, deployment, service string, source controlstate.VisitorTokenSource, _ time.Time) (controlstate.ServiceSelection, error) {
	if team != "team_1" || project != "shop" || deployment != "staging" || service != "db" {
		panic("CORS changed deployment selection")
	}
	s.calls++
	s.source = source
	return controlstate.ServiceSelection{}, s.err
}

func TestPortableCORSBodyCredentialKeepsSourceBoundary(t *testing.T) {
	for _, test := range []struct {
		name, source, authorization string
		err                         error
		status, calls               int
	}{
		{"registered key", `{"kind":"registered_key","credential":"pta_` + strings.Repeat("a", 43) + `"}`, "", nil, 200, 1},
		{"revoked key", `{"kind":"registered_key","credential":"pta_` + strings.Repeat("a", 43) + `"}`, "", controlstate.ErrPublisherIdentity, 403, 1},
		{"mixed sources", `{"kind":"registered_key","credential":"pta_` + strings.Repeat("a", 43) + `"}`, "Bearer explicit-access-token", nil, 400, 0},
		{"cookie cannot supply source", `{"kind":"device","device_id":"vdev_1234567890123456789012"}`, "", nil, 401, 0},
		{"missing credential", `{"kind":"registered_key"}`, "", nil, 400, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &corsDeploymentConnectStore{err: test.err}
			h := testHandler(t, Config{}, nil, nil, nil, Stores{DeploymentConnect: store})
			r := httptest.NewRequest(http.MethodPost, "/v1/projects/shop/deployments/staging/services/db/select?team_id=team_1", strings.NewReader(`{"source":`+test.source+`}`))
			r.Header.Set("Origin", "https://app.example")
			r.Header.Set("Content-Type", "application/json")
			r.AddCookie(&http.Cookie{Name: "__Host-tnl-browser", Value: "ambient-cookie-secret"})
			if test.authorization != "" {
				r.Header.Set("Authorization", test.authorization)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.status || store.calls != test.calls || w.Header().Get("Access-Control-Allow-Origin") != "*" ||
				w.Header().Get("Access-Control-Allow-Credentials") != "" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("CORS changed explicit source authentication", w.Code, w.Header(), w.Body.String())
			}
			if test.calls != 0 {
				source, ok := store.source.(controlstate.RegisteredKeyTokenSource)
				if !ok || source.Credential != "pta_"+strings.Repeat("a", 43) {
					t.Fatal("CORS substituted the registered credential source")
				}
			}
		})
	}
}

func TestPortableCORSParameterErrorsAreSanitized(t *testing.T) {
	h := testHandler(t, Config{}, nil, nil, nil)
	r := httptest.NewRequest(http.MethodGet, "/v1/projects/shop/deployments", nil)
	r.Header.Set("Origin", "https://app.example")
	r.Header.Set("Authorization", "Bearer must-not-appear")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 || w.Header().Get("Access-Control-Allow-Origin") != "*" || w.Header().Get("Cache-Control") != "no-store" ||
		strings.Contains(w.Body.String(), "must-not-appear") || strings.Contains(w.Body.String(), "team_id") {
		t.Fatal("parameter failure lost CORS or disclosed request details", w.Code, w.Header(), w.Body.String())
	}
}
