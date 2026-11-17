package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type lostEnrollmentResponse struct {
	result authorityv1.PublisherEnrollmentResult
	public ed25519.PublicKey
	calls  int
}

func TestEnrollmentResumesRecordedResultBeforePromotion(t *testing.T) {
	fixture, control := privateScopeFixture(t)
	d, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	state, err := d.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := opaqueid.New(opaqueid.PublisherEnrollmentPrefix)
	secret := id + ".secret"
	result := fixture.identity.enrollment()
	document, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	pending := clientstate.PendingPublisherEnrollment{EnrollmentID: id, SelectionKind: "project", SelectionKey: "project-publisher:service:" + control.service.Id, PublicKey: fixture.private.Public().(ed25519.PublicKey), SigningKey: fixture.private, EnrollmentSecret: []byte(secret), ExpiresAt: time.Now().Add(time.Minute)}
	if err := state.SavePendingPublisherEnrollment(t.Context(), pending); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordPublisherEnrollmentResult(t.Context(), id, document); err != nil {
		t.Fatal(err)
	}
	authority := &scopedAuthority{}
	n, returned, err := EnrollNative(t.Context(), state, NativeControl{Services: control}, authority, secret)
	if err != nil || authority.calls != 0 || n == nil {
		t.Fatal("recorded redemption was sent to the authority again", err)
	}
	*returned.ServiceId = "changed-result"
	if n.identity.serviceID != control.service.Id {
		t.Fatal("returned enrollment result changed native grant scope")
	}
	selected, found, err := state.SelectedPublisherIdentity(t.Context(), pending.SelectionKind, pending.SelectionKey)
	if err != nil || !found || selected.ID != result.ClientId || string(selected.PublicDocument) != string(document) {
		t.Fatal("promotion did not atomically install the original selection", err)
	}
}

func TestNativeEnrollmentRejectsOpaqueOrInconsistentSigningKey(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		d, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = d.Close() })
		state, err := d.Server(t.Context(), "https://control.example")
		if err != nil {
			t.Fatal(err)
		}
		id, _ := opaqueid.New(opaqueid.PublisherEnrollmentPrefix)
		key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
		public := append([]byte(nil), key.Public().(ed25519.PublicKey)...)
		if malformed {
			key = []byte("opaque storage value")
		} else {
			key[len(key)-1] ^= 1
		}
		if err := state.SavePendingPublisherEnrollment(t.Context(), clientstate.PendingPublisherEnrollment{EnrollmentID: id, SelectionKind: "explicit", SelectionKey: id, PublicKey: public, SigningKey: key, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatal("opaque state storage unexpectedly applied native crypto validation", err)
		}
		authority := &scopedAuthority{}
		if _, _, err := EnrollNative(t.Context(), state, NativeControl{Services: &unusedControl{}}, authority, id+".secret"); !errors.Is(err, ErrScope) || authority.calls != 0 {
			t.Fatal("invalid native key reached one-use redemption", err)
		}
	}
}

type ownerEnrollmentControl struct {
	ServiceOwnerControl
	enrollment controlv1.PublisherEnrollment
	calls      int
	request    controlv1.CreatePublisherEnrollmentRequest
}

func (*ownerEnrollmentControl) ControlURL() string { return "https://control.example" }

func (*ownerEnrollmentControl) AllocatePublisherService(context.Context, string, controlv1.AllocateServiceRequest) (controlv1.Service, error) {
	return controlv1.Service{}, errors.New("enrollment unexpectedly allocated a service")
}

func (*ownerEnrollmentControl) DeletePublisherService(context.Context, string, string) error {
	return errors.New("enrollment unexpectedly deleted a service")
}

func (c *ownerEnrollmentControl) CreatePublisherEnrollment(_ context.Context, request controlv1.CreatePublisherEnrollmentRequest) (controlv1.PublisherEnrollment, error) {
	c.calls++
	c.request = request
	return c.enrollment, nil
}

func TestEnsureServiceOwnerRecoversPendingEnrollmentWithoutIssuingAnotherGrant(t *testing.T) {
	d, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	state, err := d.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	key, _ := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	grant, _ := opaqueid.New(opaqueid.PublisherGrantPrefix)
	serviceID, _ := opaqueid.New(opaqueid.ServicePrefix)
	enrollment, _ := opaqueid.New(opaqueid.PublisherEnrollmentPrefix)
	secret := enrollment + ".one-use-secret"
	control := &ownerEnrollmentControl{enrollment: controlv1.PublisherEnrollment{Id: enrollment, TeamId: "team", Kind: "service", ServiceId: &serviceID, EnrollmentKey: secret}}
	authority := &lostEnrollmentResponse{result: authorityv1.PublisherEnrollmentResult{ClientId: id, KeyId: key, GrantId: grant, TeamId: "team", Kind: authorityv1.Service, ServiceId: &serviceID}}
	service := controlv1.Service{Id: serviceID, TeamId: "team", Name: "oauth", Protocol: controlv1.ServiceProtocolHTTP, TrustRevision: 1, Enabled: true}
	if _, _, err := EnsureServiceOwner(t.Context(), state, control, authority, service); err == nil {
		t.Fatal("lost redemption response succeeded")
	}
	if control.request.ServiceId == nil || *control.request.ServiceId != serviceID || control.request.DomainId != nil || control.request.TeamId != service.TeamId {
		t.Fatal("owner enrollment did not request its exact service")
	}
	stored, found, err := state.PendingPublisherEnrollmentForSelection(t.Context(), "project", "project-publisher:service:"+serviceID)
	if err != nil || !found || len(stored.ResultJSON) != 0 || string(stored.EnrollmentSecret) != secret {
		t.Fatalf("pending enrollment entered public metadata: %v", err)
	}
	adapter, identity, err := EnsureServiceOwner(t.Context(), state, control, authority, service)
	if err != nil || adapter == nil || identity.GrantId != grant || control.calls != 1 || authority.calls != 2 {
		t.Fatalf("pending owner enrollment did not reuse its key and one-use secret: %v", err)
	}
	if _, _, err := EnsureServiceOwner(t.Context(), state, control, authority, service); err != nil || control.calls != 1 || authority.calls != 2 {
		t.Fatalf("saved owner identity was reenrolled: %v", err)
	}
	retained, found, err := state.PublisherIdentity(t.Context(), identity.ClientId)
	if err != nil || !found || !bytes.Equal(retained.SigningKey, stored.SigningKey) {
		t.Fatal("owner promotion changed the original pending signing key", err)
	}
}

func (a *lostEnrollmentResponse) RedeemPublisherEnrollment(_ context.Context, _ string, public ed25519.PublicKey) (authorityv1.PublisherEnrollmentResult, error) {
	a.calls++
	if a.public == nil {
		a.public = append(ed25519.PublicKey(nil), public...)
		return authorityv1.PublisherEnrollmentResult{}, errors.New("response lost after server commit")
	}
	if !a.public.Equal(public) {
		return authorityv1.PublisherEnrollmentResult{}, errors.New("enrollment key was reused with another public key")
	}
	return a.result, nil
}
func (*lostEnrollmentResponse) ExchangePublisherAssertion(context.Context, string, string, string, ed25519.PrivateKey) (string, error) {
	return "access", nil
}

type unusedControl struct{ ServiceControl }

func (*unusedControl) ControlURL() string { return "https://control.example" }

func TestEnrollmentPersistsKeyBeforeOneUseRedemption(t *testing.T) {
	d, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	state, err := d.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	key, _ := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	grant, _ := opaqueid.New(opaqueid.PublisherGrantPrefix)
	service, _ := opaqueid.New(opaqueid.ServicePrefix)
	enrollment, _ := opaqueid.New(opaqueid.PublisherEnrollmentPrefix)
	a := &lostEnrollmentResponse{result: authorityv1.PublisherEnrollmentResult{ClientId: id, KeyId: key, GrantId: grant, TeamId: "team", Kind: authorityv1.Service, ServiceId: &service}}
	if _, _, err := EnrollNative(t.Context(), state, NativeControl{Services: &unusedControl{}}, a, enrollment+".secret"); err == nil {
		t.Fatal("lost enrollment response succeeded")
	}
	adapter, result, err := EnrollNative(t.Context(), state, NativeControl{Services: &unusedControl{}}, a, enrollment+".secret")
	if err != nil || result.ClientId != id || adapter == nil || a.calls != 2 {
		t.Fatalf("same-key recovery = %+v, %v", result, err)
	}
	if _, _, err := EnrollNative(t.Context(), state, NativeControl{Services: &unusedControl{}}, a, enrollment+".secret"); err != nil || a.calls != 2 {
		t.Fatalf("completed enrollment reconsumed its secret: %v", err)
	}
	loaded, result, err := LoadNative(t.Context(), state, NativeControl{Services: &unusedControl{}}, a, id)
	if err != nil || loaded == nil || result.GrantId != grant {
		t.Fatalf("saved publisher reuse = %+v, %v", result, err)
	}
	if !loaded.private.Public().(ed25519.PublicKey).Equal(a.public) {
		t.Fatal("stored signing key changed across enrollment retry")
	}
}

func TestNativeEnrollmentRequiresServicesBeforeSavingOrRedeeming(t *testing.T) {
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	state, err := database.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := opaqueid.New(opaqueid.PublisherEnrollmentPrefix)
	if err != nil {
		t.Fatal(err)
	}
	authority := &scopedAuthority{}
	if _, _, err := EnrollNative(t.Context(), state, NativeControl{}, authority, enrollment+".secret"); !errors.Is(err, ErrScope) || authority.calls != 0 {
		t.Fatal("missing service capabilities reached one-use enrollment", err)
	}
	if _, found, err := state.PendingPublisherEnrollment(t.Context(), enrollment); err != nil || found {
		t.Fatal("missing service capabilities saved a pending enrollment", found, err)
	}
}

func TestNativeEnrollmentDoesNotPromoteRetiredURLGrant(t *testing.T) {
	fixture, control := privateScopeFixture(t)
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	state, err := database.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New("url_")
	if err != nil {
		t.Fatal(err)
	}
	result := fixture.identity.enrollment()
	result.Kind, result.ServiceId = "saved_public_url", nil
	authority := &scopedAuthority{identity: result}
	enrollment, err := opaqueid.New(opaqueid.PublisherEnrollmentPrefix)
	if err != nil {
		t.Fatal(err)
	}
	clients := NativeControl{Services: control}
	if _, _, err := EnrollNative(t.Context(), state, clients, authority, enrollment+".secret"); !errors.Is(err, ErrScope) || authority.calls != 1 || authority.accesses != 0 {
		t.Fatal("retired URL enrollment was served or exchanged for access", err)
	}
	if _, found, err := state.PublisherIdentity(t.Context(), result.ClientId); err != nil || found {
		t.Fatal("retired URL grant was promoted to an installed native identity", found, err)
	}
	pending, found, err := state.PendingPublisherEnrollment(t.Context(), enrollment)
	if err != nil || !found || len(pending.ResultJSON) != 0 {
		t.Fatal("rejected native grant was recorded as a usable redemption", found, err)
	}
	owner := &ownerEnrollmentControl{}
	if _, _, err := ensureSelectedEnrollment(t.Context(), state, owner, clients, authority,
		enrollmentSelection{kind: "saved_public_url", team: result.TeamId, id: id}); !errors.Is(err, ErrScope) || owner.calls != 0 {
		t.Fatal("retired owner selection issued another URL publisher grant", err)
	}
	document, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.ImportPublisherIdentity(t.Context(), clientstate.PublisherIdentity{
		ID: result.ClientId, PublicDocument: document, SigningKey: fixture.private,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadNative(t.Context(), state, clients, authority, result.ClientId); !errors.Is(err, ErrScope) || authority.accesses != 0 {
		t.Fatal("stored retired URL grant became a native serving capability", err)
	}
}
