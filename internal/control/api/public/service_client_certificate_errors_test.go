package public

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type clientCertificateErrorsStore struct {
	ServiceClientCertificateStore
	err   error
	calls int
}

func (s *clientCertificateErrorsStore) IssueServiceClientCertificate(context.Context, string, string, string, []byte, time.Time) (controlstate.ServiceClientCertificate, error) {
	s.calls++
	return controlstate.ServiceClientCertificate{}, s.err
}

func TestServiceClientCertificateHTTPKeepsPermissionDenialSeparateFromFault(t *testing.T) {
	fault := errors.New("private certificate cleanup fault")
	outage := &pgconn.PgError{Code: "57P03", Message: "private database detail"}
	for _, test := range []struct {
		name   string
		err    error
		status int
		code   controlv1.ProblemCode
	}{
		{"permission", fmt.Errorf("issue: %w", controlstate.ErrVisitorPermission), 403, controlv1.Forbidden},
		{"permission and fault", errors.Join(controlstate.ErrVisitorPermission, fault), 500, controlv1.Internal},
		{"protected service", controlstate.ErrServiceAccess, 404, controlv1.NotFound},
		{"service and fault", errors.Join(controlstate.ErrServiceAccess, fault), 500, controlv1.Internal},
		{"known outage", outage, 503, controlv1.Unavailable},
		{"outage and fault", errors.Join(outage, fault), 500, controlv1.Internal},
		{"unexpected", fault, 500, controlv1.Internal},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &clientCertificateErrorsStore{err: test.err}
			h := &handler{dependencies: Stores{ServiceClientCertificates: store},
				authorizer: &recordingAuthorizer{principal: testControlReadPrincipal()}}
			request := httptest.NewRequest(http.MethodPost, "/v1/services/svc_fixture/client-certificates",
				strings.NewReader(`{"device_id":"vdev_fixture","csr":"Zml4dHVyZQ=="}`))
			request.Header.Set("Authorization", "Bearer fixture-control-session")
			response := httptest.NewRecorder()
			h.IssueServiceClientCertificate(response, request, "svc_fixture")
			var problem controlv1.Problem
			if response.Code != test.status || store.calls != 1 || json.Unmarshal(response.Body.Bytes(), &problem) != nil ||
				problem.Code != test.code || response.Header().Get("WWW-Authenticate") != "" ||
				strings.Contains(response.Body.String(), "private") {
				t.Fatal("certificate permission denial lost its HTTP class or disclosed a cause", response.Code, response.Body.String())
			}
		})
	}
}
