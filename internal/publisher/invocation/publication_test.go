package invocation

import (
	"context"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type foregroundShareFixture struct {
	t        *testing.T
	service  controlv1.Service
	expires  time.Time
	mutate   func(*controlv1.ShareCreation)
	requests int
}

func (f *foregroundShareFixture) CreateServiceShare(_ context.Context, key string, body controlv1.CreateShareRequest) (controlv1.ShareCreation, error) {
	f.t.Helper()
	f.requests++
	if !opaqueid.Valid(key, opaqueid.IdempotencyPrefix) || len(body.ServiceIds) != 1 || body.ServiceIds[0] != f.service.Id ||
		body.EntryServiceId != f.service.Id || !body.ExpiresAt.Equal(f.expires) {
		f.t.Fatal("guest share did not capture the actual saved service and expiration", body)
	}
	share := controlv1.ShareCreation{Link: "one-time-secret", Share: controlv1.Share{
		Id: serviceTestID(f.t, opaqueid.SharePrefix), Scope: controlv1.ShareScopeGuest,
		ServiceIds: []string{f.service.Id}, EntryServiceId: f.service.Id, GuestId: f.service.GuestId, ExpiresAt: f.expires,
	}}
	if f.mutate != nil {
		f.mutate(&share)
	}
	return share, nil
}

func TestForegroundGuestShareCapturesOnlyActualServiceWithinTrialExpiry(t *testing.T) {
	until := time.Now().Add(time.Hour).UTC()
	serviceExpiry := until.Add(-time.Minute)
	guest := clientstate.GuestSession{GuestID: serviceTestID(t, opaqueid.GuestPrefix), ExpiresAt: until}
	saved := controlv1.Service{Id: serviceTestID(t, opaqueid.ServicePrefix), GuestId: guest.GuestID, ExpiresAt: &serviceExpiry}
	f := &foregroundShareFixture{t: t, service: saved, expires: serviceExpiry}
	link, err := foregroundGuestShare(t.Context(), f, saved, guest)
	if err != nil || link != "one-time-secret" || f.requests != 1 {
		t.Fatal("guest share did not retain its one-time credential", err, f.requests)
	}
}

func TestForegroundGuestShareRejectsOtherMembershipScopeAndExpiry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*controlv1.ShareCreation)
	}{
		{"service", func(s *controlv1.ShareCreation) { s.Share.ServiceIds[0] = "another-service" }},
		{"entry", func(s *controlv1.ShareCreation) { s.Share.EntryServiceId = "another-service" }},
		{"multiple", func(s *controlv1.ShareCreation) { s.Share.ServiceIds = append(s.Share.ServiceIds, "another-service") }},
		{"scope", func(s *controlv1.ShareCreation) { s.Share.Scope = "preview" }},
		{"guest", func(s *controlv1.ShareCreation) { s.Share.GuestId = "another-guest" }},
		{"missing guest", func(s *controlv1.ShareCreation) { s.Share.GuestId = "" }},
		{"team", func(s *controlv1.ShareCreation) { s.Share.TeamId = "another-team" }},
		{"identity", func(s *controlv1.ShareCreation) { s.Share.CreatedByIdentityId = "another-identity" }},
		{"expired", func(s *controlv1.ShareCreation) { s.Share.ExpiresAt = time.Now().Add(-time.Second) }},
		{"extended", func(s *controlv1.ShareCreation) { s.Share.ExpiresAt = s.Share.ExpiresAt.Add(time.Minute) }},
		{"revoked", func(s *controlv1.ShareCreation) { s.Share.RevokedAt = new(time.Now()) }},
		{"credential", func(s *controlv1.ShareCreation) { s.Link = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			until := time.Now().Add(time.Hour).UTC()
			guest := clientstate.GuestSession{GuestID: serviceTestID(t, opaqueid.GuestPrefix), ExpiresAt: until}
			saved := controlv1.Service{Id: serviceTestID(t, opaqueid.ServicePrefix), GuestId: guest.GuestID}
			f := &foregroundShareFixture{t: t, service: saved, expires: until, mutate: tc.mutate}
			link, err := foregroundGuestShare(t.Context(), f, saved, guest)
			reason, _ := failure.ReasonOf(err)
			if err == nil || link != "" || reason != failure.ServerResponseInvalid {
				t.Fatal("accepted an unrelated or stale guest share", err)
			}
		})
	}
}

func TestForegroundGuestShareRejectsAnotherTrialsServiceBeforeRequest(t *testing.T) {
	until := time.Now().Add(time.Hour).UTC()
	guest := clientstate.GuestSession{GuestID: serviceTestID(t, opaqueid.GuestPrefix), ExpiresAt: until}
	saved := controlv1.Service{Id: serviceTestID(t, opaqueid.ServicePrefix), GuestId: serviceTestID(t, opaqueid.GuestPrefix)}
	f := &foregroundShareFixture{t: t, service: saved, expires: until}
	link, err := foregroundGuestShare(t.Context(), f, saved, guest)
	if err == nil || link != "" || f.requests != 0 {
		t.Fatal("guest share used a service from another trial", err, f.requests)
	}
}
