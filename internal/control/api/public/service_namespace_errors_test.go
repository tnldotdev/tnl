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

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type namespaceErrorsStore struct {
	ServiceStore
	err   error
	calls int
}

func (s *namespaceErrorsStore) CreateServiceAt(context.Context, string, string, string, string, controlstate.ServicePlacement, time.Time, controlstate.ServiceMetadata, *controlstate.ProjectServiceConfiguration) (controlstate.ServiceRecord, error) {
	s.calls++
	return controlstate.ServiceRecord{}, s.err
}

func TestServiceNamespaceHintDoesNotHideIndependentFault(t *testing.T) {
	hint := &controlstate.ServiceHostnameError{Namespace: "current-actor.example.test"}
	for _, test := range []struct {
		name   string
		err    error
		status int
	}{
		{"hint", fmt.Errorf("create: %w", hint), 404},
		{"hint and fault", errors.Join(hint, errors.New("private cleanup fault")), 500},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &namespaceErrorsStore{err: test.err}
			h := &handler{dependencies: Stores{Services: store},
				authorizer: &recordingAuthorizer{principal: testControlReadPrincipal()}}
			request := httptest.NewRequest(http.MethodPost, "/v1/services",
				strings.NewReader(`{"team_id":"team_test","name":"web"}`))
			request.Header.Set("Idempotency-Key", "namespace-fixture")
			request.Header.Set("Authorization", "Bearer fixture-control-session")
			response := httptest.NewRecorder()
			h.CreateService(response, request, controlv1.CreateServiceParams{})
			var problem controlv1.Problem
			if response.Code != test.status || store.calls != 1 || json.Unmarshal(response.Body.Bytes(), &problem) != nil ||
				strings.Contains(problem.Title, hint.Namespace) != (test.status == 404) ||
				strings.Contains(response.Body.String(), "private cleanup") {
				t.Fatal("namespace diagnostic suppressed an independent fault or exposed its cause", response.Code, response.Body.String())
			}
		})
	}
}
