package public

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceRunRestoredStrictInputAndTrafficProblemCodes(t *testing.T) {
	for _, test := range []struct{ name, body, code string }{
		{"null root", `null`, "invalid_request"},
		{"trailing value", `{"protocol":"http","trust_revision":"1"} {}`, "invalid_request"},
		{"unknown root", `{"protocol":"http","trust_revision":"1","unknown":true}`, "invalid_request"},
		{"null traffic", `{"protocol":"http","trust_revision":"1","traffic":null}`, "invalid_request"},
		{"zero connections", `{"protocol":"http","trust_revision":"1","traffic":{"connections":0}}`, "traffic_selection_invalid"},
		{"invalid period", `{"protocol":"http","trust_revision":"1","traffic":{"rate_per":"1ns"}}`, "traffic_selection_invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body))
			r.Header.Set("Idempotency-Key", "invalid-input")
			w := httptest.NewRecorder()
			// no publisher backend exists: rejection must precede authority.
			(&handler{}).PrepareServiceRun(w, r, "service", controlv1.PrepareServiceRunParams{})
			var problem controlv1.Problem
			if w.Code != 400 || json.Unmarshal(w.Body.Bytes(), &problem) != nil || string(problem.Code) != test.code {
				t.Fatalf("strict input status/code=%d/%s, want 400/%s", w.Code, problem.Code, test.code)
			}
		})
	}
}

type restoredRunFailureStore struct {
	ServiceRunStore
	t     *testing.T
	err   error
	calls int
}

func (s *restoredRunFailureStore) HeartbeatServiceRun(_ context.Context, service, run, token string, _ time.Time, _ controlstate.ServiceRunHealth) (controlstate.ServiceRunState, error) {
	s.t.Helper()
	s.calls++
	if service != "exact-service" || run != "exact-run" || token != "private-run-token" {
		s.t.Fatal("run failure boundary changed the exact authenticated scope")
	}
	return controlstate.ServiceRunState{}, s.err
}

func TestServiceRunRestoredFailureProblemsCorrelateWithoutCredentialLeaks(t *testing.T) {
	for _, test := range []struct {
		name    string
		err     error
		missing bool
		status  int
		code    controlv1.ProblemCode
		logged  bool
	}{
		{name: "missing store", missing: true, status: 503, code: controlv1.Unavailable},
		{name: "wrong run credential", err: fmt.Errorf("wrapped: %w", controlstate.ErrServiceAccess), status: 404, code: controlv1.NotFound},
		{name: "database failure", err: errors.New("storage unavailable"), status: 500, code: controlv1.Internal, logged: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(previous) })
			store := &restoredRunFailureStore{t: t, err: test.err}
			h := &handler{}
			if !test.missing {
				h.dependencies.ServiceRuns = store
			}
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"healthy":true,"stream_capacity":64}`))
			r.Header.Set("Authorization", "Bearer private-run-token")
			w := httptest.NewRecorder()
			h.RenewServiceRun(w, r, "exact-service", "exact-run")
			var problem controlv1.Problem
			decodeErr := json.Unmarshal(w.Body.Bytes(), &problem)
			if w.Code != test.status || w.Header().Get("Content-Type") != "application/problem+json" ||
				decodeErr != nil || problem.Code != test.code || problem.RequestId == "" {
				t.Fatalf("run failure lost its safe correlated problem: status=%d code=%s", w.Code, problem.Code)
			}
			if (logs.Len() > 0) != test.logged {
				t.Errorf("run failure logged=%t, want %t", logs.Len() > 0, test.logged)
			}
			if test.logged && !bytes.Contains(logs.Bytes(), []byte(problem.RequestId)) {
				t.Error("run failure log lost response correlation")
			}
			if test.code == controlv1.Internal {
				if !bytes.Contains(logs.Bytes(), []byte("heartbeat service run")) ||
					!bytes.Contains(logs.Bytes(), []byte("reason=server.api_internal")) {
					t.Error("run failure lost its owned operation or diagnostic reason")
				}
				if bytes.Contains(logs.Bytes(), []byte("storage unavailable")) ||
					bytes.Contains(w.Body.Bytes(), []byte("storage unavailable")) {
					t.Error("run failure disclosed the private backend cause")
				}
			}
			if bytes.Contains(logs.Bytes(), []byte("private-run-token")) || bytes.Contains(w.Body.Bytes(), []byte("private-run-token")) {
				t.Error("run failure disclosed a credential")
			}
			wantCalls := 1
			if test.missing {
				wantCalls = 0
			}
			if store.calls != wantCalls {
				t.Fatalf("run failure backend calls=%d, want %d", store.calls, wantCalls)
			}
		})
	}
}
