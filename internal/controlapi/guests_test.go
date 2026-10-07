package controlapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type guestCreationStoreStub struct {
	created controlstate.NewGuestTrial
	domain  string
	guest   controlstate.GuestTrial
	issued  int
}

func (s *guestCreationStoreStub) GuestIssuanceAllowed(context.Context, netip.Addr, time.Time) error {
	return nil
}
func (s *guestCreationStoreStub) CreateGuestTrial(_ context.Context, guest controlstate.NewGuestTrial, _ string, _ time.Time) (string, error) {
	s.created, s.domain = guest, "dom_guest"
	return s.domain, nil
}
func (s *guestCreationStoreStub) GuestTrialByAccessToken(context.Context, credentials.AccessToken) (controlstate.GuestTrial, error) {
	if s.guest.ID != "" {
		return s.guest, nil
	}
	return controlstate.GuestTrial{}, controlstate.ErrGuestUnknown
}
func (s *guestCreationStoreStub) GuestOwnsPublicURL(context.Context, string, string) (bool, error) {
	return false, nil
}
func (s *guestCreationStoreStub) GuestSourceMatches(_ controlstate.GuestTrial, prefix string) (bool, error) {
	return prefix == "192.0.2.7/32", nil
}
func (s *guestCreationStoreStub) AllocateGuestDemoNumber(context.Context, string, time.Time) (int64, error) {
	s.issued++
	return 1, nil
}

func TestGuestDemoNumberRejectsAChangedIPBeforeAllocation(t *testing.T) {
	store := &guestCreationStoreStub{guest: controlstate.GuestTrial{
		ID: "guest_trial", ExpiresAt: time.Now().Add(time.Hour),
	}}
	h := &handler{config: Config{GuestDemoEnabled: true}, guests: store}
	for _, test := range []struct {
		remote string
		status int
	}{
		{"192.0.2.8:1234", http.StatusForbidden},
		{"192.0.2.7:1234", http.StatusOK},
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/guest-demo/number", nil)
		request.RemoteAddr = test.remote
		request.Header.Set("Authorization", "Bearer guest-token")
		response := httptest.NewRecorder()
		h.AllocateGuestDemoNumber(response, request)
		if response.Code != test.status {
			t.Fatalf("number from %s = %d, body = %s", test.remote, response.Code, response.Body.String())
		}
	}
	if store.issued != 1 {
		t.Fatalf("allocated %d numbers after a changed-IP request", store.issued)
	}
}

func TestGuestCreationUsesTrustedClientIPAndManagedDomain(t *testing.T) {
	store := new(guestCreationStoreStub)
	h := &handler{
		config: Config{GuestDemoEnabled: true, ManagedDeploymentDomain: "tnl.wtf"},
		guests: store,
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/guest-demo", nil)
	request.RemoteAddr = "192.0.2.7:5432"
	response := httptest.NewRecorder()
	h.CreateGuestDemo(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("guest creation = %d, %s", response.Code, response.Body.String())
	}
	var created controlv1.GuestDemoSession
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if _, _, err := credentials.ParseAccessToken(credentials.AccessToken(created.AccessToken)); err != nil ||
		created.Namespace != store.created.NamespaceLabel+".tnl.wtf" ||
		created.TeamId != store.created.TeamID || store.domain != "dom_guest" {
		t.Fatalf("created guest = %+v, stored = %+v, error = %v", created, store.created, err)
	}
}
