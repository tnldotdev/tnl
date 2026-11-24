package invocation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type guestDemoControlStub struct {
	created int
	token   string
}

func TestGuestControlUsesDirectIPv4(t *testing.T) {
	guest := guestHTTPClient()
	guest.Timeout = time.Second
	defer guest.CloseIdleConnections()
	t.Setenv("HTTP_PROXY", "http://192.0.2.1:9")
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback")
	}
	v6 := httptest.NewUnstartedServer(http.NotFoundHandler())
	v6.Listener.Close()
	v6.Listener = listener
	v6.Start()
	defer v6.Close()
	if response, err := guest.Get(v6.URL); err == nil {
		response.Body.Close()
		t.Fatal("guest admission used IPv6")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if addr, _, err := net.SplitHostPort(r.RemoteAddr); err != nil || addr != "127.0.0.1" {
			t.Errorf("unexpected guest source: %s", r.RemoteAddr)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	response, err := guest.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal("guest admission did not reach control")
	}
}

type guestEnrollmentStub struct {
	identity    authorityv1.PublisherEnrollmentResult
	saved       controlv1.Service
	public      ed25519.PublicKey
	calls, runs int
	lost        error
	publisheridentity.ServiceControl
}

func (*guestEnrollmentStub) ControlURL() string { return "https://control.example" }

func (s *guestEnrollmentStub) EnrollGuestPublisher(_ context.Context, id string, public ed25519.PublicKey) (authorityv1.PublisherEnrollmentResult, error) {
	s.calls++
	if s.identity.ServiceId == nil || id != *s.identity.ServiceId || s.public != nil && !bytes.Equal(s.public, public) {
		return authorityv1.PublisherEnrollmentResult{}, errors.New("guest bootstrap changed its service or signing key")
	}
	s.public = bytes.Clone(public)
	if s.calls == 1 && s.lost != nil {
		return authorityv1.PublisherEnrollmentResult{}, s.lost
	}
	return s.identity, nil
}

func (s *guestEnrollmentStub) ExchangePublisherAssertion(_ context.Context, client, grant, key string, private ed25519.PrivateKey) (string, error) {
	if client != s.identity.ClientId || grant != s.identity.GrantId || key != s.identity.KeyId || !bytes.Equal(private.Public().(ed25519.PublicKey), s.public) {
		return "", errors.New("guest assertion changed its scoped identity")
	}
	return "guest-publisher-access", nil
}

func (s *guestEnrollmentStub) GetPublisherService(_ context.Context, id, token string) (controlv1.Service, error) {
	if id != s.saved.Id || token != "guest-publisher-access" {
		return controlv1.Service{}, errors.New("guest read another service or used trial management authentication")
	}
	return s.saved, nil
}

func (s *guestEnrollmentStub) PrepareServiceRun(_ context.Context, id, _ string, token string, declaration controlv1.ServiceRunDeclaration) (controlv1.ServiceRunPreparation, error) {
	if id != s.saved.Id || token != "guest-publisher-access" || declaration.Protocol != s.saved.Protocol || declaration.TrustRevision != s.saved.TrustRevision {
		return controlv1.ServiceRunPreparation{}, errors.New("guest prepared another service or used trial management authentication")
	}
	s.runs++
	return controlv1.ServiceRunPreparation{}, nil
}

func TestGuestPublicationRetriesItsDurableKeyAndUsesServicePreparation(t *testing.T) {
	state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	store, err := state.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	newID := func(prefix string) string {
		t.Helper()
		id, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	until := time.Now().UTC().Add(time.Hour)
	saved := controlv1.Service{Id: newID(opaqueid.ServicePrefix), GuestId: newID(opaqueid.GuestPrefix), Enabled: true,
		Protocol: controlv1.ServiceProtocolHTTP, Ephemeral: true, ExpiresAt: &until, TrustRevision: 1,
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "demo.example", Public: true, Port: 443}}
	lost := errors.New("lost enrollment response")
	stub := &guestEnrollmentStub{identity: authorityv1.PublisherEnrollmentResult{ClientId: newID(opaqueid.PublisherIdentityPrefix),
		KeyId: newID(opaqueid.PublisherIdentityKeyPrefix), GrantId: newID(opaqueid.PublisherGrantPrefix),
		ServiceId: &saved.Id, GuestId: saved.GuestId, Kind: authorityv1.Service, ExpiresAt: new(until)}, saved: saved, lost: lost}
	if _, err := enrollGuestNativeWithClients(t.Context(), store, saved, stub, publisheridentity.NativeControl{Services: stub}, stub); !errors.Is(err, lost) {
		t.Fatalf("lost bootstrap response = %v", err)
	}
	for range 2 {
		native, err := enrollGuestNativeWithClients(t.Context(), store, saved, stub, publisheridentity.NativeControl{Services: stub}, stub)
		if err != nil {
			t.Fatal(err)
		}
		access, err := native.Access(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := native.PrepareServiceRun(t.Context(), saved.Id, newID(opaqueid.IdempotencyPrefix), access, publisheridentity.ServiceDeclaration(saved)); err != nil {
			t.Fatal(err)
		}
		if err := native.NamespaceScope(); !errors.Is(err, publisheridentity.ErrScope) || native.Allocations != nil {
			t.Fatal("guest publication acquired allocation authority", err)
		}
	}
	if stub.calls != 2 || stub.runs != 2 {
		t.Fatalf("guest bootstrap calls=%d, signed runs=%d", stub.calls, stub.runs)
	}
}

func TestGuestCleanupDeletesItsServiceWithTrialAuthentication(t *testing.T) {
	service := "svc_1111111111111111111111"
	deletions := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deletions++
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/services/"+service || r.Header.Get("Authorization") != "Bearer trial-session" {
			t.Error("guest cleanup lost its exact service or trial credential")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	bootstrap, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken("trial-session"))
	if err != nil {
		t.Fatal(err)
	}
	allocation := &guestServiceAllocation{control: bootstrap, guest: clientstate.GuestSession{ExpiresAt: time.Now().Add(time.Hour)}, serviceID: service}
	if err := allocation.cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if deletions != 1 {
		t.Fatal("guest cleanup did not delete the service exactly once")
	}
}

func TestGuestEnrollmentReceiptKeepsActualServiceAndTrial(t *testing.T) {
	until := time.Now().Add(time.Hour)
	saved := controlv1.Service{Id: "svc_1111111111111111111111", GuestId: "gst_1111111111111111111111", ExpiresAt: &until}
	receipt := authorityv1.PublisherEnrollmentResult{Kind: authorityv1.Service,
		ServiceId: &saved.Id, GuestId: saved.GuestId, ExpiresAt: new(until)}
	if err := validateGuestEnrollment(receipt, saved); err != nil {
		t.Fatal("ordinary exact-service receipt was rejected", err)
	}
	for _, field := range []string{"guest", "team", "service", "kind", "missing expiry", "extended expiry", "elapsed expiry"} {
		t.Run(field, func(t *testing.T) {
			other := receipt
			switch field {
			case "guest":
				other.GuestId = "gst_2222222222222222222222"
			case "team":
				other.TeamId = "team"
			case "service":
				other.ServiceId = new("svc_2222222222222222222222")
			case "kind":
				other.Kind = authorityv1.Namespace
			case "missing expiry":
				other.ExpiresAt = nil
			case "extended expiry":
				other.ExpiresAt = new(until.Add(time.Second))
			case "elapsed expiry":
				other.ExpiresAt = new(time.Now().Add(-time.Second))
			}
			if err := validateGuestEnrollment(other, saved); !errors.Is(err, publisheridentity.ErrScope) {
				t.Fatal("changed receipt acquired trial publication authority", err)
			}
		})
	}
}

func (c *guestDemoControlStub) Discovery(context.Context) (controlv1.ControlDiscovery, error) {
	return controlv1.ControlDiscovery{GuestDemo: true}, nil
}

func (c *guestDemoControlStub) CreateGuestDemo(context.Context) (controlv1.GuestDemoSession, error) {
	c.created++
	return controlv1.GuestDemoSession{
		AccessToken: c.token, GuestId: "gst_0123456789abcdefghijkl",
		ExpiresAt: time.Now().UTC().Add(72 * time.Hour),
	}, nil
}

func TestGuestDemoReusesOneCredentialAndRejectsAccessOverrides(t *testing.T) {
	database, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	token, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	control := &guestDemoControlStub{token: token.String()}
	for range 2 {
		guest, err := guestForDemoWithControl(t.Context(), database, "https://control.example", PublicOptions{Demo: true}, control)
		if err != nil || guest == nil || guest.GuestID != "gst_0123456789abcdefghijkl" ||
			guest.AccessToken != token.String() || control.created != 1 {
			t.Fatalf("guest = %+v; created = %d; error = %v", guest, control.created, err)
		}
	}
	if _, err := guestForDemoWithControl(t.Context(), database, "https://control.example", PublicOptions{
		Demo: true, Anonymous: true,
	}, control); err == nil {
		t.Fatal("guest changed the visitor access policy")
	}
}

func TestGuestDemoReplacesExpiredLocalCredential(t *testing.T) {
	database, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := database.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	token, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveGuestSession(t.Context(), clientstate.GuestSession{
		GuestID: "gst_0123456789abcdefghijkl", AccessToken: token.String(),
		ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	control := &guestDemoControlStub{token: token.String()}
	guest, err := guestForDemoWithControl(t.Context(), database, "https://control.example", PublicOptions{Demo: true}, control)
	if err != nil || guest == nil || control.created != 1 || !guest.ExpiresAt.After(time.Now()) {
		t.Fatalf("replacement guest = %+v; created = %d; error = %v", guest, control.created, err)
	}
}
