package public

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type guestHumanAuthorizer struct {
	reads int
}

func (a *guestHumanAuthorizer) AuthorizeControlReads(_ context.Context, token string) (controlReadPrincipal, error) {
	a.reads++
	if token != "human-token" {
		return controlReadPrincipal{}, authorization.ErrUnauthenticated
	}
	return testControlReadPrincipal(), nil
}

type guestDeletionStore struct {
	ServiceStore
	ctx            context.Context
	service, actor string
	calls          int
	err            error
	guest          bool
}

func (s *guestDeletionStore) DeleteService(ctx context.Context, service, actor string, _ controlstate.ServiceDeleteConditions, _ time.Time) error {
	s.ctx, s.service, s.actor = ctx, service, actor
	s.calls++
	return s.err
}

func (s *guestDeletionStore) DeleteGuestService(ctx context.Context, service string, _ controlstate.GuestCredential, _ time.Time) error {
	s.ctx, s.service, s.guest = ctx, service, true
	s.calls++
	return s.err
}

func guestDeleteRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodDelete, "/v1/services/service", nil)
	r.RemoteAddr = "192.0.2.7:5432"
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func TestGuestCleanupUsesOrdinaryDeletionWithoutHumanAuthorityAfterReadyExhaustion(t *testing.T) {
	trials := guestAPIStore(t)
	trials.guest.UsedReady = controlstate.GuestReadyAllowance
	for _, issuanceEnabled := range []bool{false, true} {
		store := &guestDeletionStore{}
		human := &guestHumanAuthorizer{}
		h := &handler{config: Config{GuestDemoEnabled: issuanceEnabled}, guests: trials, authorizer: human,
			dependencies: Stores{Services: store}}
		r := guestDeleteRequest("guest-token")
		w := httptest.NewRecorder()
		h.DeleteService(w, r, trials.record.ID, controlv1.DeleteServiceParams{})
		if w.Code != 204 || store.calls != 1 || store.service != trials.record.ID || store.actor != "" ||
			store.ctx != r.Context() || !store.guest || human.reads != 0 {
			t.Fatal("cleanup became a human mutation, depended on issuance, or rejected spent READY allowance", w.Code, store.calls)
		}
	}
}

func TestGuestCleanupRetainsStateExpirySourceAndExactServiceChecks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{"expired", controlstate.ErrGuestTrialSpent, 403},
		{"source", authorization.ErrGuestIPChanged, 403},
		{"service", controlstate.ErrServiceAccess, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trials := guestAPIStore(t)
			store := &guestDeletionStore{err: tc.err}
			human := &guestHumanAuthorizer{}
			h := &handler{guests: trials, authorizer: human, dependencies: Stores{Services: store}}
			w := httptest.NewRecorder()
			h.DeleteService(w, guestDeleteRequest("guest-token"), trials.record.ID, controlv1.DeleteServiceParams{})
			if w.Code != tc.status || store.calls != 1 || human.reads != 0 {
				t.Fatal("cleanup bypassed the ordinary state check", w.Code, store.calls)
			}
		})
	}
}

func TestGuestLookupOutageNeverFallsThroughToHumanDeletion(t *testing.T) {
	for _, err := range []error{errors.New("guest storage unavailable"), errors.Join(controlstate.ErrGuestUnknown, errors.New("guest storage unavailable"))} {
		trials := guestAPIStore(t)
		trials.lookupErr = err
		human, store := &guestHumanAuthorizer{}, &guestDeletionStore{}
		h := &handler{guests: trials, authorizer: human, dependencies: Stores{Services: store}}
		w := httptest.NewRecorder()
		h.DeleteService(w, guestDeleteRequest("human-token"), trials.record.ID, controlv1.DeleteServiceParams{})
		if w.Code != 503 || store.calls != 0 || human.reads != 0 {
			t.Fatal("trial lookup outage became human management", w.Code, store.calls, human.reads)
		}
	}
}

func TestUnrecognizedTrialBearerMayUseOnlyNormalHumanAuthentication(t *testing.T) {
	for _, tc := range []struct {
		token  string
		status int
		calls  int
	}{
		{"human-token", 204, 1},
		{"bad-token", 401, 0},
		{"exact-publisher-token", 401, 0},
	} {
		trials := guestAPIStore(t)
		human, store := &guestHumanAuthorizer{}, &guestDeletionStore{}
		h := &handler{guests: trials, authorizer: human, dependencies: Stores{Services: store}}
		r, w := guestDeleteRequest(tc.token), httptest.NewRecorder()
		r.URL.RawQuery = "expected_service_revision=1"
		h.DeleteService(w, r, trials.record.ID, controlv1.DeleteServiceParams{ExpectedServiceRevision: new(int64(1))})
		if w.Code != tc.status || human.reads != 1 || store.calls != tc.calls ||
			tc.calls != 0 && (store.actor != "identity_1" || store.ctx != r.Context()) {
			t.Fatal("unrecognized trial bearer bypassed human authentication", tc.token, w.Code)
		}
	}
}

func TestGuestTrialNeverBecomesAControlSessionPrincipal(t *testing.T) {
	trials := guestAPIStore(t)
	human := &guestHumanAuthorizer{}
	h := &handler{guests: trials, authorizer: human, dependencies: Stores{Services: &guestDeletionStore{}}}
	r := guestDeleteRequest("guest-token")
	w := httptest.NewRecorder()
	h.ListServices(w, r, controlv1.ListServicesParams{TeamId: "not-a-guest-team"})
	if w.Code != 401 || human.reads != 1 {
		t.Fatal("trial acquired generic human service management", w.Code)
	}
}

type guestHumanAuthentication struct {
	AuthorizationStore
	calls int
}

func (s *guestHumanAuthentication) AuthenticateAccessToken(context.Context, credentials.AccessToken, time.Time) (controlstate.ControlPrincipal, error) {
	s.calls++
	return controlstate.ControlPrincipal{}, controlstate.ErrControlAuthentication
}

func TestHandlerGuestWiringDoesNotWrapHumanAuthorization(t *testing.T) {
	trials, sessions := guestAPIStore(t), &guestHumanAuthentication{}
	mux, err := NewHandler(Config{GuestDemoEnabled: true, ManagedDomain: "example.test"},
		Stores{Guests: trials, Services: &guestDeletionStore{}}, sessions, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/v1/services?team_id="+guestAPIID(t, opaqueid.TeamPrefix), nil)
	r.Header.Set("Authorization", "Bearer guest-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 401 || sessions.calls != 1 {
		t.Fatal("handler wiring converted a trial into generic human authorization", w.Code, sessions.calls)
	}
}
