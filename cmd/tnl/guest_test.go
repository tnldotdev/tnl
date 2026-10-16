package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
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
	nativeauth.NativeControl
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
	if _, err := publisheridentity.VerifyRun(s.public, proof, id, retry); err != nil {
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
	route := controlv1.PublicURL{Id: newID(opaqueid.PublicURLPrefix), TeamId: newID(opaqueid.TeamPrefix), LifecycleState: controlv1.Enabled, Purpose: controlv1.Demo, ServiceProtocol: controlv1.Http, Ephemeral: true}
	lost := errors.New("lost enrollment response")
	stub := &guestEnrollmentStub{identity: controlv1.GuestPublisherIdentity{ClientId: newID(opaqueid.PublisherIdentityPrefix), KeyId: newID(opaqueid.PublisherIdentityKeyPrefix), GrantId: newID(opaqueid.PublisherGrantPrefix), PublicUrlId: route.Id, TeamId: route.TeamId}, lost: lost}
	if _, err := enrollGuestNativeWithClients(t.Context(), store, route, stub, stub, stub); !errors.Is(err, lost) {
		t.Fatalf("lost bootstrap response = %v", err)
	}
	for range 2 {
		native, err := enrollGuestNativeWithClients(t.Context(), store, route, stub, stub, stub)
		if err != nil {
			t.Fatal(err)
		}
		control := nativePublicationControl(native, nil)
		if _, err := control.CreatePublishRun(t.Context(), route.Id, newID(opaqueid.IdempotencyPrefix)); err != nil {
			t.Fatal(err)
		}
		if _, err := control.CreatePublicURL(t.Context(), controlv1.CreatePublicURLRequest{}, "retry"); !errors.Is(err, nativeauth.ErrScope) {
			t.Fatalf("guest acquired a broader creation scope: %v", err)
		}
	}
	if stub.calls != 2 || stub.runs != 2 {
		t.Fatalf("guest bootstrap calls=%d, signed runs=%d", stub.calls, stub.runs)
	}
}

func TestGuestAssignmentCannotCreateOrDeleteAnotherURL(t *testing.T) {
	member, ephemeral := "mem_assigned", true
	prefixes := []string{"192.0.2.7/32"}
	route := controlv1.PublicURL{Id: "url_assigned", TeamId: "tm_guest", DomainId: "dom_guest", MembershipId: &member, CanonicalHostname: "demo-1.guest.example", PublicUrlScope: controlv1.Member, Purpose: controlv1.Demo, ServiceProtocol: controlv1.Http, Ephemeral: true, Target: "http://127.0.0.1:3000", AllowedIpPrefixes: &prefixes}
	control := guestPublicationControl{assigned: route}
	body := controlv1.CreatePublicURLRequest{TeamId: route.TeamId, DomainId: route.DomainId, MembershipId: route.MembershipId, CanonicalHostname: route.CanonicalHostname, PublicUrlScope: route.PublicUrlScope, Purpose: route.Purpose, Ephemeral: &ephemeral, Target: route.Target, AllowedIpPrefixes: &prefixes}
	if assigned, err := control.CreatePublicURL(t.Context(), body, "retry"); err != nil || assigned.Id != route.Id {
		t.Fatalf("guest assignment = %+v, %v", assigned, err)
	}
	body.CanonicalHostname = "another.guest.example"
	if _, err := control.CreatePublicURL(t.Context(), body, "retry"); !errors.Is(err, nativeauth.ErrScope) {
		t.Fatalf("guest assignment created another URL: %v", err)
	}
	body.CanonicalHostname = route.CanonicalHostname
	otherIP := []string{"192.0.2.8/32"}
	body.AllowedIpPrefixes = &otherIP
	if _, err := control.CreatePublicURL(t.Context(), body, "retry"); !errors.Is(err, nativeauth.ErrScope) {
		t.Fatalf("guest assignment changed the original source IP: %v", err)
	}
	if err := control.DeletePublicURL(t.Context(), "url_another"); !errors.Is(err, nativeauth.ErrScope) {
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
		guest, err := guestForDemoWithControl(t.Context(), database, "https://control.example", publishCommand{Demo: true}, control)
		if err != nil || guest == nil || guest.Namespace != "guest-01234567.example" ||
			guest.AccessToken != token.String() || control.created != 1 {
			t.Fatalf("guest = %+v; created = %d; error = %v", guest, control.created, err)
		}
	}
	if _, err := guestForDemoWithControl(t.Context(), database, "https://control.example", publishCommand{
		Demo: true, tunnelFlags: tunnelFlags{Anonymous: true},
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
	guest, err := guestForDemoWithControl(t.Context(), database, "https://control.example", publishCommand{Demo: true}, control)
	if err != nil || guest == nil || control.created != 1 || !guest.ExpiresAt.After(time.Now()) {
		t.Fatalf("replacement guest = %+v; created = %d; error = %v", guest, control.created, err)
	}
}
