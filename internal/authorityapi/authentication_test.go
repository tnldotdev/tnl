package authorityapi

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
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestControlAuthenticationRejectsAmbiguousHeadersBeforeStore(t *testing.T) {
	// Any call through this embedded nil store panics, proving parsing happens first.
	h := &handler{store: struct{ Store }{}}
	for _, values := range [][]string{nil, {"Bearer first", "Bearer second"}, {"Bearer first,second"}} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header["Authorization"] = values
		response := httptest.NewRecorder()
		if _, ok := h.authenticateControlRequest(response, request); ok || response.Code != http.StatusUnauthorized {
			t.Fatalf("headers %q: authenticated=%v, status=%d", values, ok, response.Code)
		}
	}
}

func TestControlAuthenticationMapsCredentialAndStoreFailures(t *testing.T) {
	databaseFailure := errors.New("database unavailable")
	for _, test := range []struct {
		name       string
		store      Store
		wantStatus int
		wantCode   authorityv1.ProblemCode
		wantLog    bool
	}{
		{name: "store unavailable", wantStatus: http.StatusServiceUnavailable, wantCode: authorityv1.Unavailable, wantLog: true},
		{name: "invalid credential", store: &controlAuthenticationStoreStub{authenticationErr: fmt.Errorf("wrapped: %w", controlstate.ErrControlAuthentication)}, wantStatus: http.StatusUnauthorized, wantCode: authorityv1.Unauthenticated},
		{name: "database failure", store: &controlAuthenticationStoreStub{authenticationErr: databaseFailure}, wantStatus: http.StatusServiceUnavailable, wantCode: authorityv1.Unavailable, wantLog: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(previous) })

			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set("Authorization", "Bearer access-token-secret")
			response := httptest.NewRecorder()
			if _, ok := (&handler{store: test.store}).authenticateControlRequest(response, request); ok {
				t.Fatal("authentication succeeded")
			}
			var problem authorityv1.Problem
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if response.Code != test.wantStatus || response.Header().Get("Content-Type") != "application/problem+json" || problem.Code != test.wantCode {
				t.Fatalf("response = %d %q %#v", response.Code, response.Header().Get("Content-Type"), problem)
			}
			if test.wantLog != (logs.Len() != 0) {
				t.Fatalf("log = %q", logs.String())
			}
			if test.wantLog && (!bytes.Contains(logs.Bytes(), []byte(problem.RequestId)) || bytes.Contains(logs.Bytes(), []byte("access-token-secret"))) {
				t.Fatalf("log does not safely correlate request %q: %q", problem.RequestId, logs.String())
			}
		})
	}
}

func TestLogoutMapsConcurrentRevocationToUnauthenticated(t *testing.T) {
	store := &controlAuthenticationStoreStub{
		principal: controlstate.ControlPrincipal{SessionID: "control_session_1", IdentityID: "identity_1"},
		revokeErr: controlstate.ErrControlAuthentication,
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	NewHandler(Config{}, store).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || response.Header().Get("Content-Type") != "application/problem+json" || response.Header().Get("WWW-Authenticate") == "" || store.revocations != 1 {
		t.Fatalf("logout response = %d %q %q, revocations = %d", response.Code, response.Header().Get("Content-Type"), response.Body.String(), store.revocations)
	}
}

type controlAuthenticationStoreStub struct {
	Store
	principal         controlstate.ControlPrincipal
	authenticationErr error
	revokeErr         error
	revocations       int
}

func (s controlAuthenticationStoreStub) AuthenticateAccessToken(
	context.Context,
	credentials.AccessToken,
	int64,
	time.Time,
) (controlstate.ControlPrincipal, error) {
	return s.principal, s.authenticationErr
}

func (s *controlAuthenticationStoreStub) RevokeControlSession(context.Context, controlstate.ControlPrincipal, time.Time) error {
	s.revocations++
	return s.revokeErr
}
