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
	failureproblem "github.com/tnldotdev/tnl/internal/failure/problem"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
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
		{"empty namespace", &controlstate.ServiceHostnameError{}, 500},
		{"noncanonical namespace", &controlstate.ServiceHostnameError{Namespace: "Current-Actor.example.test"}, 500},
		{"oversized namespace", &controlstate.ServiceHostnameError{Namespace: strings.Repeat("private", 1000)}, 500},
		{"terminal control in namespace", &controlstate.ServiceHostnameError{Namespace: "private\x1b[31m\nsecret"}, 500},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &namespaceErrorsStore{err: test.err}
			h := &handler{dependencies: Stores{Services: store},
				authorizer: &recordingAuthorizer{principal: testControlReadPrincipal()}}
			request := httptest.NewRequest(http.MethodPost, "/v1/services",
				strings.NewReader(`{"team_id":"team_test","name":"web"}`))
			request.Header.Set("Idempotency-Key", "namespace-fixture")
			request.Header.Set("Authorization", "Bearer fixture-control-session")
			request.Header.Set("Accept", "text/html,application/xhtml+xml")
			response := httptest.NewRecorder()
			h.CreateService(response, request, controlv1.CreateServiceParams{})
			var problem controlv1.Problem
			if response.Code != test.status || store.calls != 1 || json.Unmarshal(response.Body.Bytes(), &problem) != nil ||
				strings.Contains(problem.Title, hint.Namespace) != (test.status == 404) ||
				strings.Contains(response.Body.String(), "private") || strings.Contains(response.Body.String(), "secret") {
				t.Fatal("namespace diagnostic suppressed an independent fault or exposed its cause", response.Code, response.Body.String())
			}
			var namespace any
			if problem.Details != nil {
				namespace = (*problem.Details)["allowed_namespace"]
			}
			if test.status == 404 && namespace != hint.Namespace || test.status != 404 && namespace != nil {
				t.Fatal("namespace problem lost its structured hint or retained it for an independent fault", response.Body.String())
			}
			var envelope map[string]any
			if json.Unmarshal(response.Body.Bytes(), &envelope) != nil || len(envelope) != 7 ||
				problem.Type != failureproblem.URL(string(problem.Code)) || problem.Status != test.status ||
				problem.Detail != problem.Title || !opaqueid.Valid(problem.RequestId, opaqueid.RequestPrefix) ||
				response.Header().Get("Content-Type") != "application/problem+json" ||
				response.Header().Get("Link") != "<"+problem.Type+">; rel=\"help\"" ||
				test.status == 404 && problem.Title != hint.Error() {
				t.Fatal("namespace details changed the problem identity, correlation, help or representation", response.Body.String())
			}
		})
	}
}
