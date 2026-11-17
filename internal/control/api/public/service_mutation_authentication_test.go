package public

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceMutationAuthenticationStore struct {
	serviceConfigurationStore
	gets, deletes int
}

func (s *serviceMutationAuthenticationStore) GetService(_ context.Context, service, actor string) (controlstate.ServiceRecord, error) {
	s.calls++
	s.gets++
	if service != "svc_aaaaaaaaaaaaaaaaaaaaaa" || actor != testControlReadPrincipal().identityID {
		panic("service read changed the exact service or authenticated actor")
	}
	return controlstate.ServiceRecord{ID: service, ServiceMetadata: controlstate.ServiceMetadata{Protocol: "http", TrustRevision: 7}}, nil
}

func (s *serviceMutationAuthenticationStore) DeleteService(_ context.Context, service, actor string, _ controlstate.ServiceDeleteConditions, _ time.Time) error {
	s.calls++
	s.deletes++
	if service != "svc_aaaaaaaaaaaaaaaaaaaaaa" || actor != testControlReadPrincipal().identityID {
		panic("service deletion changed the exact service or authenticated actor")
	}
	return nil
}

func TestServiceMutationsAuthenticateBeforeServiceStore(t *testing.T) {
	const path = "/v1/services/svc_aaaaaaaaaaaaaaaaaaaaaa"
	for _, operation := range []struct {
		name, method, body string
		status             int
		gets, deletes      int
	}{
		{"configure", http.MethodPut, `{"protocol":"http","publisher_pool":false,"expected_trust_revision":"7","unconditional_configuration":true,"configuration":{"target":"localhost:4000"}}`, http.StatusOK, 0, 0},
		{"get", http.MethodGet, "", http.StatusOK, 1, 0},
		{"delete", http.MethodDelete, "", http.StatusNoContent, 0, 1},
	} {
		t.Run(operation.name, func(t *testing.T) {
			for _, authentication := range []struct {
				name, header string
				err          error
				tokens       []string
				allowed      bool
			}{
				{name: "missing bearer"},
				{name: "wrong scheme", header: "Basic supplied-token"},
				{name: "empty bearer", header: "Bearer"},
				{name: "rejected bearer", header: "Bearer exact-rejected-token", err: authorization.ErrUnauthenticated, tokens: []string{"exact-rejected-token"}},
				{name: "authenticated", header: "Bearer exact-access-token", tokens: []string{"exact-access-token"}, allowed: true},
			} {
				t.Run(authentication.name, func(t *testing.T) {
					store := &serviceMutationAuthenticationStore{}
					authorizer := &recordingAuthorizer{principal: testControlReadPrincipal(), readErr: authentication.err}
					h := &handler{
						dependencies: Stores{Services: store}, authorizer: authorizer,
						// deletion may check guest authentication before control
						// authentication; only service-store work is forbidden.
						guests: &guestCreationStoreStub{},
					}
					requestPath := path
					if operation.method == http.MethodDelete {
						requestPath += "?expected_service_revision=7"
					}
					request := httptest.NewRequest(operation.method, requestPath, strings.NewReader(operation.body))
					if authentication.header != "" {
						request.Header.Set("Authorization", authentication.header)
					}
					response := httptest.NewRecorder()
					controlv1.HandlerWithOptions(h, controlv1.StdHTTPServerOptions{}).ServeHTTP(response, request)
					status, calls, gets, deletes := http.StatusUnauthorized, 0, 0, 0
					if authentication.allowed {
						status, calls, gets, deletes = operation.status, 1, operation.gets, operation.deletes
					}
					if response.Code != status || store.calls != calls || store.gets != gets || store.deletes != deletes {
						t.Fatalf("status=%d service calls=%d get=%d delete=%d; want %d/%d/%d/%d: %s",
							response.Code, store.calls, store.gets, store.deletes, status, calls, gets, deletes, response.Body.String())
					}
					if !slices.Equal(authorizer.readTokens, authentication.tokens) {
						t.Fatalf("authentication tokens=%q, want %q", authorizer.readTokens, authentication.tokens)
					}
					if !authentication.allowed {
						var problem controlv1.Problem
						if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil || problem.Code != controlv1.Unauthenticated {
							t.Fatal("rejected authentication lost its problem code", err, response.Body.String())
						}
					}
				})
			}
		})
	}
}
