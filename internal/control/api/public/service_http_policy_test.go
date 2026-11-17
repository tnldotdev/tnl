package public

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type httpPolicyAuthorizationStore struct {
	auth  controlstate.ServiceHTTPRun
	calls int
	err   error
}

func (s *httpPolicyAuthorizationStore) ReadPublisherVisitorPolicy(_ context.Context, scope visitorscope.Scope, run string, number int64, token string, _ int64, _ time.Time) (controlv1.VisitorPolicyUpdate, error) {
	s.auth = serviceHTTPRun(scope.ID, run, token, number)
	s.calls++
	return controlv1.VisitorPolicyUpdate{}, s.err
}

func TestServiceHTTPPolicyRequiresRunBearerAndExactRunScope(t *testing.T) {
	for _, test := range []struct {
		name, bearer  string
		number        int
		err           error
		status, calls int
	}{
		{"authenticated run", "run-secret", 7, nil, 200, 1},
		{"missing bearer", "", 7, nil, 401, 0},
		{"wrong number", "run-secret", 0, nil, 400, 0},
		{"state denial", "run-secret", 7, controlstate.ErrServiceAccess, 403, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := "svc_" + strings.Repeat("S", 22)
			store := &httpPolicyAuthorizationStore{err: test.err}
			h := &handler{dependencies: Stores{VisitorPolicy: store}}
			body := fmt.Sprintf(`{"resource":{"kind":"service","id":%q},"run_id":"run","run_number":"%d","after_revision":"0"}`, service, test.number)
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
			if test.bearer != "" {
				r.Header.Set("Authorization", "Bearer "+test.bearer)
			}
			response := httptest.NewRecorder()
			h.ReadPublisherVisitorPolicy(response, r)
			if response.Code != test.status || store.calls != test.calls || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("HTTP policy boundary changed", response.Code, store.calls, response.Body.String())
			}
			if store.calls != 0 && (store.auth.Subject != (visitorscope.Scope{Kind: visitorscope.Service, ID: service}) ||
				store.auth.RunID != "run" || store.auth.Number != int64(test.number) || store.auth.Token != credentials.ServiceRunToken(test.bearer)) {
				t.Fatal("HTTP policy changed the exact publisher run or token")
			}
		})
	}
}
