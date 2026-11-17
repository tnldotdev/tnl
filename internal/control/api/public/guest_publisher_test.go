package public

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type guestEnrollmentStore struct {
	credential controlstate.GuestCredential
	service    string
	key        ed25519.PublicKey
	now        time.Time
	identity   controlstate.PublisherIdentity
	calls      int
	err        error
}

func (s *guestEnrollmentStore) EnrollGuestPublisher(_ context.Context, credential controlstate.GuestCredential, service string, key ed25519.PublicKey, now time.Time) (controlstate.PublisherIdentity, error) {
	s.calls++
	s.credential, s.service, s.key, s.now = credential, service, slices.Clone(key), now
	return s.identity, s.err
}

func guestEnrollmentRequest(service, key string) *http.Request {
	body, _ := json.Marshal(controlv1.EnrollGuestPublisherRequest{ServiceId: service, PublicKey: key})
	r := httptest.NewRequest(http.MethodPost, "/v1/guest-demo/publisher", strings.NewReader(string(body)))
	r.RemoteAddr = "[::ffff:192.0.2.7]:4321"
	r.Header.Set("Authorization", "Bearer guest-token")
	r.Header.Set("Forwarded", "for=198.51.100.8")
	r.Header.Set("X-Forwarded-For", "198.51.100.8")
	return r
}

func TestGuestEnrollmentUsesExactServiceGrantActualTrialOwnerAndStoredExpiry(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	guest, service := guestAPIID(t, opaqueid.GuestPrefix), guestAPIID(t, opaqueid.ServicePrefix)
	store := &guestEnrollmentStore{identity: controlstate.PublisherIdentity{
		ID: guestAPIID(t, opaqueid.PublisherIdentityPrefix), KeyID: guestAPIID(t, opaqueid.PublisherIdentityKeyPrefix),
		GrantID: guestAPIID(t, opaqueid.PublisherGrantPrefix), GuestID: guest, ExpiresAt: &until,
		Scope: controlstate.PublisherScope{GuestID: guest, Kind: "service", ServiceID: service},
	}}
	h := &handler{config: Config{GuestDemoEnabled: true}, dependencies: Stores{GuestPublishers: store}}
	w := httptest.NewRecorder()
	h.EnrollGuestPublisher(w, guestEnrollmentRequest(service, base64.RawURLEncoding.EncodeToString(public)))
	var identity controlv1.PublisherEnrollmentResult
	if err := json.Unmarshal(w.Body.Bytes(), &identity); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || store.calls != 1 || store.service != service || !slices.Equal(store.key, public) ||
		store.credential.Token != "guest-token" || store.credential.SourceIP != netip.MustParseAddr("192.0.2.7") || store.now.IsZero() ||
		identity.GuestId != guest || identity.TeamId != "" || identity.Kind != "service" ||
		identity.ServiceId == nil || *identity.ServiceId != service || identity.ExpiresAt == nil || !identity.ExpiresAt.Equal(until) ||
		identity.Namespace != nil || identity.DomainId != nil || strings.Contains(w.Body.String(), `"public_url_id"`) ||
		strings.Contains(w.Body.String(), `"team_id"`) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("guest enrollment changed credential source, exact grant, owner, or fixed expiration", w.Code, store.calls)
	}
}

func TestGuestEnrollmentRejectsOldResourceFieldsAndInvalidKeysBeforeState(t *testing.T) {
	service := guestAPIID(t, opaqueid.ServicePrefix)
	encoded := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	for _, body := range []string{
		`{}`,
		`{"public_url_id":"old-url","public_key":"` + encoded + `"}`,
		`{"service_id":"wrong-id","public_key":"` + encoded + `"}`,
		`{"service_id":"` + service + `","public_key":"AA"}`,
		`{"service_id":"` + service + `","public_key":"` + encoded + `","source_ip":"198.51.100.8"}`,
	} {
		store := &guestEnrollmentStore{}
		h := &handler{config: Config{GuestDemoEnabled: true}, dependencies: Stores{GuestPublishers: store}}
		r := guestEnrollmentRequest(service, encoded)
		r.Body = io.NopCloser(strings.NewReader(body))
		w := httptest.NewRecorder()
		h.EnrollGuestPublisher(w, r)
		if w.Code != 400 || store.calls != 0 {
			t.Fatal("invalid guest enrollment reached state", w.Code, store.calls)
		}
	}
}

func TestGuestEnrollmentPreservesStateAuthenticationAndAvailabilityDenials(t *testing.T) {
	service := guestAPIID(t, opaqueid.ServicePrefix)
	key := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	for _, tc := range []struct {
		err    error
		status int
		code   controlv1.ProblemCode
	}{
		{controlstate.ErrGuestUnknown, 401, controlv1.Unauthenticated},
		{controlstate.ErrPublisherIdentity, 401, controlv1.Unauthenticated},
		{controlstate.ErrGuestTrialSpent, 403, controlv1.GuestTrialExhausted},
		{authorization.ErrGuestIPChanged, 403, controlv1.GuestIpChanged},
		{errors.New("storage unavailable"), 503, controlv1.Unavailable},
	} {
		store := &guestEnrollmentStore{err: tc.err}
		h := &handler{config: Config{GuestDemoEnabled: true}, dependencies: Stores{GuestPublishers: store}}
		w := httptest.NewRecorder()
		h.EnrollGuestPublisher(w, guestEnrollmentRequest(service, key))
		if w.Code != tc.status || store.calls != 1 || !strings.Contains(w.Body.String(), `"code":"`+string(tc.code)+`"`) {
			t.Fatal("guest enrollment changed a state-owned denial", w.Code)
		}
	}
}

func TestPublisherGrantProjectionCarriesOnlyItsActualOwner(t *testing.T) {
	for _, guest := range []bool{false, true} {
		row := controlstatedb.ControlPublisherGrant{ID: "grant", Kind: "service", ServiceID: pgtype.Text{String: "service", Valid: true}, Protocols: []string{"http"}}
		owner, absent := "team_id", "guest_id"
		if guest {
			owner, absent = absent, owner
			row.GuestID = pgtype.Text{String: "guest", Valid: true}
			row.TeamID = pgtype.Text{String: "not-present"}
		} else {
			row.TeamID = pgtype.Text{String: "team", Valid: true}
			row.GuestID = pgtype.Text{String: "not-present"}
		}
		encoded, err := json.Marshal(publisherGrantResponse(row))
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		if len(fields[owner]) == 0 || len(fields[absent]) != 0 {
			t.Fatal("publisher grant fabricated or omitted its owner")
		}
	}
}
