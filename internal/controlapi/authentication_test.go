package controlapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestRouteSessionAuthenticationRejectsAmbiguousHeadersBeforeStore(t *testing.T) {
	// Any call through this embedded nil store panics, proving parsing happens first.
	h := &handler{store: struct{ Store }{}}
	for _, values := range [][]string{nil, {"Bearer first", "Bearer second"}, {"Bearer first,second"}} {
		request := httptest.NewRequest(http.MethodPost, "/", nil)
		request.Header["Authorization"] = values
		response := httptest.NewRecorder()
		if _, ok := h.authenticateRouteSessionRequest(response, request, "route_session_1", 1); ok || response.Code != http.StatusUnauthorized {
			t.Fatalf("headers %q: authenticated=%v, status=%d", values, ok, response.Code)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "bEaReR opaque-token")
	if token, ok := requestBearerToken(request); !ok || token != "opaque-token" {
		t.Fatalf("mixed-case bearer = %q, %v", token, ok)
	}
}

func TestRouteSessionAuthenticationMapsCredentialAndStoreFailures(t *testing.T) {
	databaseFailure := errors.New("database unavailable")
	for _, test := range []struct {
		name       string
		store      Store
		wantStatus int
		wantCode   controlv1.ProblemCode
		wantLog    bool
	}{
		{name: "store unavailable", wantStatus: http.StatusServiceUnavailable, wantCode: controlv1.Unavailable, wantLog: true},
		{name: "invalid credential", store: routeAuthenticationStoreStub{err: fmt.Errorf("wrapped: %w", controlstate.ErrRouteSessionCredential)}, wantStatus: http.StatusUnauthorized, wantCode: controlv1.Unauthenticated},
		{name: "database failure", store: routeAuthenticationStoreStub{err: databaseFailure}, wantStatus: http.StatusServiceUnavailable, wantCode: controlv1.Unavailable, wantLog: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(previous) })

			request := httptest.NewRequest(http.MethodPost, "/", nil)
			request.Header.Set("Authorization", "Bearer route-session-secret")
			response := httptest.NewRecorder()
			if _, ok := (&handler{store: test.store}).authenticateRouteSessionRequest(response, request, "route_session_1", 1); ok {
				t.Fatal("authentication succeeded")
			}
			var problem controlv1.Problem
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if response.Code != test.wantStatus || response.Header().Get("Content-Type") != "application/problem+json" || problem.Code != test.wantCode {
				t.Fatalf("response = %d %q %#v", response.Code, response.Header().Get("Content-Type"), problem)
			}
			if test.wantLog != (logs.Len() != 0) {
				t.Fatalf("log = %q", logs.String())
			}
			if test.wantLog && (!bytes.Contains(logs.Bytes(), []byte(problem.RequestId)) || bytes.Contains(logs.Bytes(), []byte("route-session-secret"))) {
				t.Fatalf("log does not safely correlate request %q: %q", problem.RequestId, logs.String())
			}
		})
	}
}

type routeAuthenticationStoreStub struct {
	Store
	err error
}

func (s routeAuthenticationStoreStub) RouteSessionAuthentication(
	context.Context,
	string,
	uint64,
	credentials.RouteSessionToken,
) (controlstate.RouteSessionAuthentication, error) {
	return controlstate.RouteSessionAuthentication{}, s.err
}
