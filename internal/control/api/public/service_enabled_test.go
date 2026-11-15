package public

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceEnabledStore struct {
	ServiceStore
	calls   int
	enabled bool
	err     error
}

func (s *serviceEnabledStore) SetServiceEnabled(_ context.Context, service, actor string, enabled bool, _ time.Time) (controlstate.ServiceRecord, error) {
	if service != "svc_aaaaaaaaaaaaaaaaaaaaaa" || actor != testPublicURLReadPrincipal().identityID {
		panic("availability changed the exact service or authenticated manager")
	}
	s.calls++
	s.enabled = enabled
	return controlstate.ServiceRecord{ID: service, Enabled: enabled}, s.err
}

func TestServiceEnabledWireRequiresExplicitBooleanAndManagement(t *testing.T) {
	for _, test := range []struct {
		name, body string
		err        error
		status     int
		calls      int
		enabled    bool
	}{
		{"suspend", `{"enabled":false}`, nil, 200, 1, false},
		{"enable", `{"enabled":true}`, nil, 200, 1, true},
		{"missing", `{}`, nil, 400, 0, false},
		{"null", `{"enabled":null}`, nil, 400, 0, false},
		{"string", `{"enabled":"false"}`, nil, 400, 0, false},
		{"unknown", `{"enabled":false,"target":"private"}`, nil, 400, 0, false},
		{"denied", `{"enabled":true}`, controlstate.ErrServiceAccess, 404, 1, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &serviceEnabledStore{err: test.err}
			h := &handler{store: store, dependencies: Stores{Services: store}, authorizer: &recordingAuthorizer{principal: testPublicURLReadPrincipal()}}
			r := httptest.NewRequest(http.MethodPut, "/v1/services/svc_aaaaaaaaaaaaaaaaaaaaaa/enabled", strings.NewReader(test.body))
			r.Header.Set("Authorization", "Bearer access-token")
			w := httptest.NewRecorder()
			controlv1.HandlerWithOptions(h, controlv1.StdHTTPServerOptions{
				Middlewares: []controlv1.MiddlewareFunc{publisherRequestSourceMiddleware},
			}).ServeHTTP(w, r)
			if w.Code != test.status || store.calls != test.calls || store.enabled != test.enabled || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("availability decoding or authorization changed", w.Code, store.calls, w.Body.String())
			}
			if w.Code == http.StatusOK {
				var saved controlv1.Service
				if err := json.Unmarshal(w.Body.Bytes(), &saved); err != nil || saved.Id != "svc_aaaaaaaaaaaaaaaaaaaaaa" || saved.Enabled != test.enabled {
					t.Fatal("availability changed the saved identity", err)
				}
			}
		})
	}
}
