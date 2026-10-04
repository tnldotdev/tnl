package controlapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type guestCreationStoreStub struct {
	created controlstate.NewGuestTrial
	domain  string
}

func (s *guestCreationStoreStub) GuestIssuanceAllowed(context.Context, netip.Addr, time.Time) error {
	return nil
}
func (s *guestCreationStoreStub) CreateGuestTrial(_ context.Context, guest controlstate.NewGuestTrial, domain, _ string, _ time.Time) error {
	s.created, s.domain = guest, domain
	return nil
}
func (s *guestCreationStoreStub) GuestTrialByAccessToken(context.Context, credentials.AccessToken) (controlstate.GuestTrial, error) {
	return controlstate.GuestTrial{}, controlstate.ErrGuestUnknown
}
func (s *guestCreationStoreStub) GuestOwnsPublicURL(context.Context, string, string) (bool, error) {
	return false, nil
}
func (s *guestCreationStoreStub) GuestSourceMatches(_ controlstate.GuestTrial, prefix string) (bool, error) {
	return prefix == netip.PrefixFrom(s.created.SourceIP, s.created.SourceIP.BitLen()).String(), nil
}
func (s *guestCreationStoreStub) AllocateGuestDemoNumber(context.Context, string, time.Time) (int64, error) {
	return 1, nil
}

func TestGuestCreationUsesTrustedClientIPAndManagedDomain(t *testing.T) {
	const secret = "hosted-service-secret-012345678901"
	authority := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/service/guest-domain" || r.Header.Get("Authorization") != "Bearer "+secret ||
			!strings.HasPrefix(r.URL.Query().Get("namespace_label"), "guest-") {
			t.Errorf("guest namespace request path or authentication was wrong: %s", r.URL.Path)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"domain_id": "dom_guest", "managed_domain": "tnl.wtf", "namespace_available": true, "dns_authority_reference": "da_guest",
		})
	}))
	defer authority.Close()
	client, err := authorityclient.New(authority.URL, authority.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	store := new(guestCreationStoreStub)
	h := &handler{
		config: Config{GuestDemoEnabled: true, ManagedDeploymentDomain: "tnl.wtf", HostedSecret: secret},
		guests: store, guestAuthority: client,
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
		store.created.SourceIP.String() != "192.0.2.7" || strings.Contains(response.Body.String(), "192.0.2.7") ||
		created.Namespace != store.created.NamespaceLabel+".tnl.wtf" ||
		created.TeamId != store.created.TeamID || store.domain != "dom_guest" {
		t.Fatalf("created guest = %+v, stored = %+v, error = %v", created, store.created, err)
	}
}
