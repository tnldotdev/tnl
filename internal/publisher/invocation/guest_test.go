package invocation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type guestDemoControlStub struct {
	created int
	token   string
}

type guestEnrollmentStub struct {
	identity    controlv1.GuestPublisherIdentity
	public      ed25519.PublicKey
	calls, runs int
	lost        error
	publisheridentity.NativeControl
}

func (s *guestEnrollmentStub) EnrollGuestPublisher(_ context.Context, id string, public ed25519.PublicKey) (controlv1.GuestPublisherIdentity, error) {
	s.calls++
	if id != s.identity.PublicUrlId || s.public != nil && !bytes.Equal(s.public, public) {
		return controlv1.GuestPublisherIdentity{}, errors.New("guest bootstrap changed its URL or signing key")
	}
	s.public = bytes.Clone(public)
	if s.calls == 1 && s.lost != nil {
		return controlv1.GuestPublisherIdentity{}, s.lost
	}
	return s.identity, nil
}

func (s *guestEnrollmentStub) ExchangePublisherAssertion(_ context.Context, client, grant, key string, private ed25519.PrivateKey) (string, error) {
	if client != s.identity.ClientId || grant != s.identity.GrantId || key != s.identity.KeyId || !bytes.Equal(private.Public().(ed25519.PublicKey), s.public) {
		return "", errors.New("guest assertion changed its scoped identity")
	}
	return "guest-publisher-access", nil
}

func (s *guestEnrollmentStub) CreatePublisherRun(_ context.Context, id, retry, token, proof string) (controlv1.PublishRunSetup, error) {
	if id != s.identity.PublicUrlId || token != "guest-publisher-access" {
		return controlv1.PublishRunSetup{}, errors.New("guest used a bootstrap session to create a run")
	}
	if _, err := publisherproof.VerifyRun(s.public, proof, id, retry); err != nil {
		return controlv1.PublishRunSetup{}, err
	}
	s.runs++
	return controlv1.PublishRunSetup{}, nil
}

func TestGuestPublicationRetriesEnrollmentWithItsDurableKeyAndUsesSignedRuns(t *testing.T) {
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
	publicURL := controlv1.PublicURL{Id: newID(opaqueid.PublicURLPrefix), TeamId: newID(opaqueid.TeamPrefix), LifecycleState: controlv1.Enabled, Purpose: controlv1.Demo, ServiceProtocol: controlv1.Http, Ephemeral: true}
	lost := errors.New("lost enrollment response")
	stub := &guestEnrollmentStub{identity: controlv1.GuestPublisherIdentity{ClientId: newID(opaqueid.PublisherIdentityPrefix), KeyId: newID(opaqueid.PublisherIdentityKeyPrefix), GrantId: newID(opaqueid.PublisherGrantPrefix), PublicUrlId: publicURL.Id, TeamId: publicURL.TeamId}, lost: lost}
	if _, err := enrollGuestNativeWithClients(t.Context(), store, publicURL, stub, stub, stub); !errors.Is(err, lost) {
		t.Fatalf("lost bootstrap response = %v", err)
	}
	for range 2 {
		native, err := enrollGuestNativeWithClients(t.Context(), store, publicURL, stub, stub, stub)
		if err != nil {
			t.Fatal(err)
		}
		control := nativePublicationControl(native, nil)
		if _, err := control.CreatePublishRun(t.Context(), publicURL.Id, newID(opaqueid.IdempotencyPrefix)); err != nil {
			t.Fatal(err)
		}
		if _, ok := any(control).(publisher.PublicURLManagementClient); ok {
			t.Fatal("guest acquired a broader creation scope")
		}
	}
	if stub.calls != 2 || stub.runs != 2 {
		t.Fatalf("guest bootstrap calls=%d, signed runs=%d", stub.calls, stub.runs)
	}
}

func TestGuestAssignmentCannotDeleteAnotherURL(t *testing.T) {
	publicURL := controlv1.PublicURL{Id: "url_assigned"}
	control := guestPublicationControl{assigned: publicURL}
	if err := control.DeletePublicURL(t.Context(), "url_another"); !errors.Is(err, publisheridentity.ErrScope) {
		t.Fatalf("guest assignment deleted another URL: %v", err)
	}
}

func (c *guestDemoControlStub) Discovery(context.Context) (controlv1.ControlDiscovery, error) {
	return controlv1.ControlDiscovery{GuestDemo: true}, nil
}

func (c *guestDemoControlStub) CreateGuestDemo(context.Context) (controlv1.GuestDemoSession, error) {
	c.created++
	return controlv1.GuestDemoSession{
		AccessToken: c.token, GuestId: "gst_0123456789abcdefghijkl",
		TeamId: "tm_0123456789abcdefghijkl", MembershipId: "mem_0123456789abcdefghijkl",
		DomainId: "dom_0123456789abcdefghijkl", Namespace: "guest-01234567.example",
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
		if err != nil || guest == nil || guest.Namespace != "guest-01234567.example" ||
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
		TeamID: "tm_0123456789abcdefghijkl", MembershipID: "mem_0123456789abcdefghijkl",
		DomainID: "dom_0123456789abcdefghijkl", Namespace: "guest-01234567.example",
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
