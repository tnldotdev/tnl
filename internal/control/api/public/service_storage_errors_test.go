package public

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceStorageErrors struct {
	ServiceStore
	t     *testing.T
	err   error
	calls int
}

func (s *serviceStorageErrors) CreateServiceAt(_ context.Context, team, actor, name, key string, _ controlstate.ServicePlacement, _ time.Time, metadata controlstate.ServiceMetadata, configuration *controlstate.ProjectServiceConfiguration) (controlstate.ServiceRecord, error) {
	s.t.Helper()
	if team != "team_test" || actor != testControlReadPrincipal().identityID || name != "web" || key != "storage-fixture" ||
		metadata.Protocol != "tcp" || configuration != nil {
		s.t.Fatal("storage failure changed the authenticated creation scope")
	}
	s.calls++
	return controlstate.ServiceRecord{}, s.err
}

func (s *serviceStorageErrors) ListServices(_ context.Context, team, actor, cursor string) ([]controlstate.ServiceRecord, string, error) {
	s.t.Helper()
	if team != "team_test" || actor != testControlReadPrincipal().identityID || cursor != "" {
		s.t.Fatal("storage failure changed the authenticated inventory scope")
	}
	s.calls++
	return nil, "", s.err
}

func TestServiceOperationsSeparateStorageOutageAndFault(t *testing.T) {
	outage := &pgconn.PgError{Code: "57P03", Message: "private database credential"}
	fault := errors.New("private independent cleanup fault")
	for _, operation := range []string{"create", "list"} {
		t.Run(operation, func(t *testing.T) {
			for _, test := range []struct {
				name   string
				err    error
				status int
				code   controlv1.ProblemCode
			}{
				{"database unavailable", outage, 503, controlv1.Unavailable},
				{"wrapped outage", fmt.Errorf("storage: %w", outage), 503, controlv1.Unavailable},
				{"connection refused", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, 503, controlv1.Unavailable},
				{"independent known outages", errors.Join(outage, syscall.ECONNRESET), 503, controlv1.Unavailable},
				{"unexpected fault", fault, 500, controlv1.Internal},
				{"protocol fault", &pgconn.PgError{Code: "08P01", Message: "private protocol fault"}, 500, controlv1.Internal},
				{"outage with fault", errors.Join(outage, fault), 500, controlv1.Internal},
				{"wrapped outage with fault", fmt.Errorf("storage: %w", errors.Join(outage, fault)), 500, controlv1.Internal},
				{"cancellation with fault", errors.Join(context.Canceled, fault), 500, controlv1.Internal},
				{"permission denial", controlstate.ErrServiceAccess, 404, controlv1.NotFound},
				{"permission with independent fault", errors.Join(controlstate.ErrServiceAccess, fault), 500, controlv1.Internal},
				{"permission with independent outage", errors.Join(controlstate.ErrServiceAccess, outage), 500, controlv1.Internal},
			} {
				t.Run(test.name, func(t *testing.T) {
					var logs bytes.Buffer
					previous := log.Writer()
					log.SetOutput(&logs)
					defer log.SetOutput(previous)
					store := &serviceStorageErrors{t: t, err: test.err}
					h := &handler{dependencies: Stores{Services: store},
						authorizer: &recordingAuthorizer{principal: testControlReadPrincipal()}}
					request := httptest.NewRequest(http.MethodPost, "/v1/services",
						strings.NewReader(`{"team_id":"team_test","name":"web"}`))
					if operation == "list" {
						request = httptest.NewRequest(http.MethodGet, "/v1/services?team_id=team_test", nil)
					}
					request.Header.Set("Authorization", "Bearer private-control-session")
					request.Header.Set("Idempotency-Key", "storage-fixture")
					response := httptest.NewRecorder()
					if operation == "create" {
						h.CreateService(response, request, controlv1.CreateServiceParams{})
					} else {
						h.ListServices(response, request, controlv1.ListServicesParams{TeamId: "team_test"})
					}
					var problem controlv1.Problem
					if response.Code != test.status || store.calls != 1 || json.Unmarshal(response.Body.Bytes(), &problem) != nil ||
						problem.Code != test.code || problem.RequestId == "" || response.Header().Get("Content-Type") != "application/problem+json" {
						t.Fatalf("service %s status=%d calls=%d body=%s", operation, response.Code, store.calls, response.Body.String())
					}
					for _, secret := range []string{"private-control-session", "private database", "private protocol", "private independent"} {
						if strings.Contains(response.Body.String(), secret) {
							t.Fatal("service storage failure disclosed a private cause")
						}
					}
					if response.Header().Get("WWW-Authenticate") != "" {
						t.Fatal("service storage failure became an authentication challenge")
					}
					if test.status < 500 {
						if logs.Len() != 0 {
							t.Fatal("permission denial was reported as an infrastructure fault")
						}
						return
					}
					reason := failure.ServerAPIInternal
					if test.status == 503 {
						reason = failure.ServerUnavailable
					}
					if !strings.Contains(logs.String(), problem.RequestId) || !strings.Contains(logs.String(), operation+" service") ||
						!strings.Contains(logs.String(), "reason="+string(reason)) {
						t.Fatal("service storage failure lost its correlated operation and classification", logs.String())
					}
				})
			}
		})
	}
}
