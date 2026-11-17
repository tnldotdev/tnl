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
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type guestCreationStoreStub struct {
	created       controlstate.NewGuestTrial
	domain        string
	guest         controlstate.GuestTrial
	record        controlstate.ServiceRecord
	allocation    controlstate.AllocateGuestDemoServiceRequest
	allocate      func(controlstate.AllocateGuestDemoServiceRequest) error
	lookupErr     error
	issuanceErr   error
	createErr     error
	issued, calls int
}

func (s *guestCreationStoreStub) GuestIssuanceAllowed(context.Context, netip.Addr, time.Time) error {
	return s.issuanceErr
}
func (s *guestCreationStoreStub) CreateGuestTrial(_ context.Context, guest controlstate.NewGuestTrial, domain string, _ time.Time) (controlstate.GuestTrial, error) {
	s.created, s.domain = guest, domain
	if s.createErr != nil {
		return controlstate.GuestTrial{}, s.createErr
	}
	s.guest.ID = guest.ID
	return s.guest, nil
}
func (s *guestCreationStoreStub) GuestTrialByAccessToken(_ context.Context, token credentials.AccessToken) (controlstate.GuestTrial, error) {
	if s.lookupErr != nil {
		return controlstate.GuestTrial{}, s.lookupErr
	}
	if token == "guest-token" && s.guest.ID != "" {
		return s.guest, nil
	}
	return controlstate.GuestTrial{}, controlstate.ErrGuestUnknown
}
func (s *guestCreationStoreStub) AllocateGuestDemoService(_ context.Context, request controlstate.AllocateGuestDemoServiceRequest) (controlstate.ServiceRecord, error) {
	s.calls++
	s.allocation = request
	if s.allocate != nil {
		if err := s.allocate(request); err != nil {
			return controlstate.ServiceRecord{}, err
		}
	}
	s.issued++
	return s.record, nil
}

func guestAPIID(t *testing.T, prefix string) string {
	t.Helper()
	id, err := opaqueid.New(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func guestAPIStore(t *testing.T) *guestCreationStoreStub {
	t.Helper()
	until := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	guestID := guestAPIID(t, opaqueid.GuestPrefix)
	return &guestCreationStoreStub{guest: controlstate.GuestTrial{ID: guestID, ExpiresAt: until},
		record: controlstate.ServiceRecord{ID: guestAPIID(t, opaqueid.ServicePrefix), GuestID: guestID,
			Name: "demo", Enabled: true, Protocol: "http", Ephemeral: true, ExpiresAt: &until, TrustRevision: 1,
			Endpoint: &controlstate.ServiceEndpoint{Hostname: "demo-1.guest.example.test", Port: 443, Public: true}}}
}

func guestAllocationRequest(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/guest-demo/services", strings.NewReader(body))
	r.RemoteAddr = "192.0.2.7:5432"
	r.Header.Set("Authorization", "Bearer guest-token")
	r.Header.Set("Idempotency-Key", "allocation")
	r.Header.Set("Forwarded", "for=198.51.100.4")
	r.Header.Set("X-Forwarded-For", "198.51.100.4")
	return r
}

func TestGuestCreationUsesTrustedClientIPAndCommittedExpiryWithoutHumanOwner(t *testing.T) {
	store := guestAPIStore(t)
	h := &handler{config: Config{GuestDemoEnabled: true, ManagedDomain: "tnl.wtf"}, guests: store}
	r := httptest.NewRequest(http.MethodPost, "/v1/guest-demo", nil)
	r.RemoteAddr = "[::ffff:192.0.2.7]:5432"
	r.Header.Set("X-Forwarded-For", "198.51.100.4")
	w := httptest.NewRecorder()
	h.CreateGuestDemo(w, r)
	var created controlv1.GuestDemoSession
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusCreated || created.AccessToken != string(store.created.Token) || created.GuestId != store.created.ID ||
		!created.ExpiresAt.Equal(store.guest.ExpiresAt) || store.domain != "tnl.wtf" ||
		store.created.SourceIP != netip.MustParseAddr("192.0.2.7") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("trial creation lost its accepted source, committed expiry, or credential")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 3 {
		t.Fatal("trial creation returned synthetic identity, team, membership, or DNS values")
	}
}

func TestGuestAllocationForwardsActualCredentialListenerAndSourceToState(t *testing.T) {
	store := guestAPIStore(t)
	h := &handler{config: Config{GuestDemoEnabled: true}, guests: store}
	r := guestAllocationRequest(`{"target":"http://127.0.0.1:3000","require_post_quantum":true}`)
	w := httptest.NewRecorder()
	h.AllocateGuestDemoService(w, r, controlv1.AllocateGuestDemoServiceParams{})
	var saved controlv1.Service
	if err := json.Unmarshal(w.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	got := store.allocation
	if w.Code != http.StatusCreated || store.calls != 1 || got.Target != "http://127.0.0.1:3000" ||
		got.Credential.Token != "guest-token" || got.Credential.SourceIP != netip.MustParseAddr("192.0.2.7") ||
		got.IdempotencyKey != "allocation" || !got.RequirePostQuantum || got.Now.IsZero() ||
		saved.Id != store.record.ID || saved.GuestId != store.guest.ID || saved.TeamId != "" ||
		saved.ExpiresAt == nil || !saved.ExpiresAt.Equal(store.guest.ExpiresAt) || strings.Contains(w.Body.String(), `"team_id"`) {
		t.Fatal("allocation changed trial ownership, observed source, immutable intent, or fixed expiry")
	}
}

func TestGuestAllocationSourceAndExpiryDecisionsRemainInState(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   controlv1.ProblemCode
	}{
		{authorization.ErrGuestIPChanged, 403, controlv1.GuestIpChanged},
		{controlstate.ErrGuestTrialSpent, 403, controlv1.GuestTrialExhausted},
		{controlstate.ErrGuestUnknown, 401, controlv1.Unauthenticated},
		{controlstate.ErrServiceConflict, 409, controlv1.Conflict},
		{errors.New("database unavailable"), 503, controlv1.Unavailable},
	} {
		t.Run(string(tc.code), func(t *testing.T) {
			store := guestAPIStore(t)
			store.allocate = func(controlstate.AllocateGuestDemoServiceRequest) error { return tc.err }
			h := &handler{config: Config{GuestDemoEnabled: true}, guests: store}
			w := httptest.NewRecorder()
			h.AllocateGuestDemoService(w, guestAllocationRequest(`{"target":"http://127.0.0.1:3000"}`), controlv1.AllocateGuestDemoServiceParams{})
			if w.Code != tc.status || store.calls != 1 || !strings.Contains(w.Body.String(), `"code":"`+string(tc.code)+`"`) {
				t.Fatal("allocation changed the state-owned denial", w.Code, w.Body.String())
			}
		})
	}
}

func TestGuestAllocationRejectsUnboundTargetsAndBodySourceBeforeState(t *testing.T) {
	for _, body := range []string{
		`{}`, `{"target":"http://127.0.0.1"}`, `{"target":"https://127.0.0.1:3000"}`,
		`{"target":"http://example.test:3000"}`, `{"target":"http://127.0.0.1:0"}`,
		`{"target":"http://127.0.0.1:65536"}`, `{"target":"http://user@127.0.0.1:3000"}`,
		`{"target":"http://127.0.0.1:3000/path"}`, `{"target":"http://127.0.0.1:3000?query"}`,
		`{"target":"http://127.0.0.1:3000#fragment"}`,
		`{"target":"http://127.0.0.1:3000","source_ip":"198.51.100.4"}`,
		`{"target":"http://127.0.0.1:3000","team_id":"synthetic"}`,
		`{"target":"http://127.0.0.1:3000","expires_at":"2099-01-01T00:00:00Z"}`,
	} {
		store := guestAPIStore(t)
		h := &handler{config: Config{GuestDemoEnabled: true}, guests: store}
		w := httptest.NewRecorder()
		h.AllocateGuestDemoService(w, guestAllocationRequest(body), controlv1.AllocateGuestDemoServiceParams{})
		if w.Code != 400 || store.calls != 0 {
			t.Fatal("invalid allocation reached state", body, w.Code)
		}
	}
	for _, target := range []string{"http://127.0.0.1:3000/", "http://[::1]:3000"} {
		if !validGuestTarget(target) {
			t.Fatal("bound loopback listener was rejected", target)
		}
	}
}

func TestGuestRequestsRejectUnspecifiedZonedAndMissingPeerAddresses(t *testing.T) {
	for _, remote := range []string{"0.0.0.0:3000", "[::]:3000", "[::ffff:0.0.0.0]:3000", "[fe80::1%en0]:3000", "192.0.2.7", "hostname:3000"} {
		r := guestAllocationRequest(`{"target":"http://127.0.0.1:3000"}`)
		r.RemoteAddr = remote
		store := guestAPIStore(t)
		h := &handler{config: Config{GuestDemoEnabled: true}, guests: store}
		w := httptest.NewRecorder()
		h.AllocateGuestDemoService(w, r, controlv1.AllocateGuestDemoServiceParams{})
		if w.Code != 400 || store.calls != 0 {
			t.Fatal("untrusted source reached guest state", remote, w.Code)
		}
	}
}

func TestGuestIssuanceLimitIsCheckedBeforeAndDuringCreation(t *testing.T) {
	for _, atCommit := range []bool{false, true} {
		store := guestAPIStore(t)
		if atCommit {
			store.createErr = controlstate.ErrGuestIssuance
		} else {
			store.issuanceErr = controlstate.ErrGuestIssuance
		}
		h := &handler{config: Config{GuestDemoEnabled: true}, guests: store}
		r := httptest.NewRequest(http.MethodPost, "/v1/guest-demo", nil)
		r.RemoteAddr = "192.0.2.7:1234"
		w := httptest.NewRecorder()
		h.CreateGuestDemo(w, r)
		if w.Code != 429 || w.Header().Get("Retry-After") != "3600" ||
			!strings.Contains(w.Body.String(), `"code":"guest_issuance_limited"`) {
			t.Fatal("guest issuance lost its limit response", w.Code)
		}
	}
}

func TestGuestIssuanceFailuresKeepSafeCorrelatedOperatorDiagnostics(t *testing.T) {
	const sensitive = "Bearer guest-credential-private source-ip-digest-private -----BEGIN PRIVATE KEY-----"
	for _, tc := range []struct {
		name, operation string
		atCommit        bool
		cause           error
		sqlstate        bool
	}{
		{"issuance lookup", "check guest issuance", false, &pgconn.PgError{Code: "23514", Message: sensitive}, true},
		{"trial insert", "create guest trial", true, fmt.Errorf("save trial: %w", &pgconn.PgError{Code: "23514", Detail: sensitive}), true},
		{"malformed database error", "create guest trial", true, &pgconn.PgError{Code: "23514\n" + sensitive, Message: sensitive}, false},
		{"active request database cancellation", "check guest issuance", false, fmt.Errorf("database canceled: %w", context.Canceled), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(previous) })
			store := guestAPIStore(t)
			if tc.atCommit {
				store.createErr = tc.cause
			} else {
				store.issuanceErr = tc.cause
			}
			h := &handler{config: Config{GuestDemoEnabled: true}, guests: store}
			r := httptest.NewRequest(http.MethodPost, "/v1/guest-demo", strings.NewReader("private-full-request"))
			r.RemoteAddr = "192.0.2.7:1234"
			r.Header.Set("Authorization", sensitive)
			w := httptest.NewRecorder()
			h.CreateGuestDemo(w, r)
			var problem controlv1.Problem
			if json.Unmarshal(w.Body.Bytes(), &problem) != nil || w.Code != 503 || problem.Code != controlv1.Unavailable ||
				problem.RequestId == "" || w.Header().Get("Content-Type") != "application/problem+json" {
				t.Fatal("guest failure lost its safe unavailable response and request correlation", w.Code)
			}
			if strings.Contains(w.Body.String(), "23514") || strings.Contains(w.Body.String(), "sqlstate") {
				t.Fatal("guest response exposed database diagnostics")
			}
			if !strings.Contains(logs.String(), tc.operation) || !strings.Contains(logs.String(), "request_id="+problem.RequestId) ||
				!strings.Contains(logs.String(), "reason="+string(failure.ServerAPIInternal)) ||
				strings.Contains(logs.String(), "sqlstate=23514") != tc.sqlstate {
				t.Fatal("guest failure lost its concrete operation, cause classification, or request correlation")
			}
			for _, value := range []string{sensitive, "guest-credential-private", "source-ip-digest-private",
				"-----BEGIN PRIVATE KEY-----", "private-full-request", string(store.created.Token)} {
				if value != "" && (strings.Contains(w.Body.String(), value) || strings.Contains(logs.String(), value)) {
					t.Fatal("guest failure exposed credentials or private request data")
				}
			}
		})
	}
}

func TestGuestIssuanceCancellationDoesNotWriteOrLogUnavailable(t *testing.T) {
	for _, atCommit := range []bool{false, true} {
		t.Run(fmt.Sprintf("atCommit=%t", atCommit), func(t *testing.T) {
			var logs bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(previous) })
			store := guestAPIStore(t)
			if atCommit {
				store.createErr = context.Canceled
			} else {
				store.issuanceErr = context.Canceled
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			r := httptest.NewRequest(http.MethodPost, "/v1/guest-demo", nil).WithContext(ctx)
			r.RemoteAddr = "192.0.2.7:1234"
			w := httptest.NewRecorder()
			(&handler{config: Config{GuestDemoEnabled: true}, guests: store}).CreateGuestDemo(w, r)
			if w.Body.Len() != 0 || w.Flushed || logs.Len() != 0 {
				t.Fatal("canceled guest request emitted an unavailable problem or operator failure")
			}
		})
	}
}
