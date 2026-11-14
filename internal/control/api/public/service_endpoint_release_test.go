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

type serviceEndpointReleaseStore struct {
	PublicURLStore
	ServiceStore
	calls int
	err   error
}

func (s *serviceEndpointReleaseStore) ReleaseServiceEndpoint(_ context.Context, service, actor string, revision int64, port int, _ time.Time) (controlstate.ServiceRecord, error) {
	s.calls++
	if service != "svc_aaaaaaaaaaaaaaaaaaaaaa" || actor != testPublicURLReadPrincipal().identityID || revision != 7 || port != 25443 {
		panic("release changed its exact binding or authenticated actor")
	}
	return controlstate.ServiceRecord{ID: service, EndpointRevision: 8, ServiceMetadata: controlstate.ServiceMetadata{Protocol: "tcp", TrustRevision: 2, Endpoint: &controlstate.ServiceEndpoint{Hostname: "api.example.test"}}}, s.err
}

func TestServiceEndpointReleaseWireBoundsAndConflictMessages(t *testing.T) {
	for _, test := range []struct {
		body    string
		err     error
		status  int
		calls   int
		message string
	}{
		{`{"expected_endpoint_revision":"7","expected_port":25443}`, nil, 200, 1, ""},
		{`{"expected_endpoint_revision":"7","expected_port":25443}`, controlstate.ErrServiceConflict, 409, 1, "read the current service"},
		{`{"expected_endpoint_revision":"7","expected_port":25443}`, controlstate.ErrServiceEndpointPublic, 409, 1, "disable public access"},
		{`{"expected_endpoint_revision":"7","expected_port":25443}`, controlstate.ErrServiceEndpointDNSPending, 409, 1, "wait for cleanup"},
		{`{"expected_endpoint_revision":"7","expected_port":25443}`, controlstate.ErrServiceAccess, 404, 1, "not found"},
		{`{}`, nil, 400, 0, ""},
		{`null`, nil, 400, 0, ""},
		{`{"expected_endpoint_revision":7,"expected_port":25443}`, nil, 400, 0, ""},
		{`{"expected_endpoint_revision":"0","expected_port":25443}`, nil, 400, 0, ""},
		{`{"expected_endpoint_revision":"7","expected_port":0}`, nil, 400, 0, ""},
		{`{"expected_endpoint_revision":"7","expected_port":65536}`, nil, 400, 0, ""},
		{`{"expected_endpoint_revision":"7","expected_port":443}`, nil, 400, 0, ""},
		{`{"expected_endpoint_revision":"7","expected_port":25443,"public":false}`, nil, 400, 0, ""},
		{`{"expected_endpoint_revision":"7","expected_port":25443} {}`, nil, 400, 0, ""},
		{`{"expected_trust_revision":"7","expected_port":25443}`, nil, 400, 0, ""},
	} {
		t.Run(test.body+"/"+test.message, func(t *testing.T) {
			store := &serviceEndpointReleaseStore{err: test.err}
			h := &handler{store: store, dependencies: Stores{Services: store}, authorizer: &recordingAuthorizer{principal: testPublicURLReadPrincipal()}}
			r := httptest.NewRequest(http.MethodPost, "/v1/services/svc_aaaaaaaaaaaaaaaaaaaaaa/endpoint/release", strings.NewReader(test.body))
			r.Header.Set("Authorization", "Bearer access-token")
			w := httptest.NewRecorder()
			h.ReleaseServiceEndpoint(w, r, "svc_aaaaaaaaaaaaaaaaaaaaaa")
			if w.Code != test.status || store.calls != test.calls || !strings.Contains(w.Body.String(), test.message) {
				t.Fatal("release decoding or diagnostics changed", w.Code, store.calls, w.Body.String())
			}
			if w.Code == 200 {
				var released controlv1.Service
				if err := json.Unmarshal(w.Body.Bytes(), &released); err != nil || released.EndpointRevision != 8 || released.TrustRevision != 2 || released.Endpoint == nil || released.Endpoint.Port != 0 || released.Endpoint.Public {
					t.Fatal("release lost exact zero-port binding", released, err)
				}
			}
		})
	}
}
