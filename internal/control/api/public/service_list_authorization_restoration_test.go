package public

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type restoredServiceListStore struct {
	ServiceStore
	t     *testing.T
	calls int
}

type restoredSessionFailureStore struct {
	AuthorizationStore
	err error
}

func (s *restoredSessionFailureStore) AuthenticateAccessToken(context.Context, credentials.AccessToken, time.Time) (controlstate.ControlPrincipal, error) {
	return controlstate.ControlPrincipal{}, s.err
}

func TestServiceRestoredCurrentSessionFailureClassificationAndLogging(t *testing.T) {
	outage := errors.New("session storage unavailable")
	for _, test := range []struct {
		name   string
		err    error
		status int
		code   controlv1.ProblemCode
		want   error
		logged bool
	}{
		{"invalid session", controlstate.ErrControlAuthentication, 401, controlv1.Unauthenticated, authorization.ErrUnauthenticated, false},
		{"storage outage", outage, 503, controlv1.Unavailable, authorization.ErrUnavailable, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			authorizer := localAuthorizer{store: &restoredSessionFailureStore{err: test.err}}
			if _, err := authorizer.AuthorizeControlReads(t.Context(), "private-session-token"); !errors.Is(err, test.want) ||
				test.logged && !errors.Is(err, outage) {
				t.Fatal("current session failure lost classification or its independent cause", err)
			}
			var logs bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(previous) })
			store := &restoredServiceListStore{t: t}
			h := &handler{authorizer: authorizer, dependencies: Stores{Services: store}}
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Authorization", "Bearer private-session-token")
			w := httptest.NewRecorder()
			h.ListServices(w, r, controlv1.ListServicesParams{TeamId: "exact-team"})
			var problem controlv1.Problem
			if w.Code != test.status || json.Unmarshal(w.Body.Bytes(), &problem) != nil || problem.Code != test.code ||
				problem.RequestId == "" || store.calls != 0 || (logs.Len() > 0) != test.logged ||
				w.Header().Get("Content-Type") != "application/problem+json" {
				t.Fatal("current session failure reached service state or lost its safe problem", w.Code, store.calls)
			}
			if test.logged && !bytes.Contains(logs.Bytes(), []byte(problem.RequestId)) {
				t.Error("session outage lost log/response correlation")
			}
			if bytes.Contains(logs.Bytes(), []byte("private-session-token")) || bytes.Contains(w.Body.Bytes(), []byte("private-session-token")) {
				t.Error("session failure disclosed its credential")
			}
		})
	}
}

func (s *restoredServiceListStore) ListServices(_ context.Context, team, actor, cursor string) ([]controlstate.ServiceRecord, string, error) {
	s.t.Helper()
	s.calls++
	if team != "exact-team" || actor != testControlReadPrincipal().identityID || cursor != "exact-cursor" {
		s.t.Fatal("management list changed the exact authenticated team, actor, or cursor")
	}
	return []controlstate.ServiceRecord{}, "", nil
}

func TestServiceRestoredManagementListAuthenticatesOnceAndForwardsExactCursor(t *testing.T) {
	store := &restoredServiceListStore{t: t}
	authorizer := &recordingAuthorizer{principal: testControlReadPrincipal()}
	h := &handler{dependencies: Stores{Services: store}, authorizer: authorizer}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer exact-access-token")
	w := httptest.NewRecorder()
	cursor := "exact-cursor"
	h.ListServices(w, r, controlv1.ListServicesParams{TeamId: "exact-team", Cursor: &cursor})
	var page controlv1.ServicePage
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.Services == nil ||
		len(page.Services) != 0 || page.NextCursor != nil || store.calls != 1 ||
		!reflect.DeepEqual(authorizer.readTokens, []string{"exact-access-token"}) {
		t.Fatal("management list changed its one-read authentication or empty-page contract")
	}
}
