package identity

import (
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
	n, returned, err := EnrollNative(t.Context(), state, control, authority, secret)
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
		if _, _, err := EnrollNative(t.Context(), state, &unusedControl{}, authority, id+".secret"); !errors.Is(err, ErrScope) || authority.calls != 0 {
			t.Fatal("invalid native key reached one-use redemption", err)
		}
	}
}

type ownerEnrollmentControl struct {
	NativeControl
	enrollment controlv1.PublisherEnrollment
	calls      int
}

func (c *ownerEnrollmentControl) CreatePublisherEnrollment(context.Context, controlv1.CreatePublisherEnrollmentRequest) (controlv1.PublisherEnrollment, error) {
	c.calls++
	return c.enrollment, nil
}

func TestEnsureOwnerRecoversPendingEnrollmentWithoutIssuingAnotherGrant(t *testing.T) {
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
	url, _ := opaqueid.New(opaqueid.PublicURLPrefix)
	enrollment, _ := opaqueid.New(opaqueid.PublisherEnrollmentPrefix)
	secret := enrollment + ".one-use-secret"
	control := &ownerEnrollmentControl{enrollment: controlv1.PublisherEnrollment{Id: enrollment, TeamId: "team", Kind: "saved_public_url", PublicUrlId: &url, EnrollmentKey: secret}}
	authority := &lostEnrollmentResponse{result: authorityv1.PublisherEnrollmentResult{ClientId: id, KeyId: key, GrantId: grant, TeamId: "team", Kind: "saved_public_url", PublicUrlId: &url}}
	publicURL := controlv1.PublicURL{Id: url, TeamId: "team", CanonicalHostname: "oauth.example", Purpose: controlv1.Oauth, LifecycleState: controlv1.Enabled}
	if _, _, err := EnsureOwner(t.Context(), state, control, authority, publicURL); err == nil {
		t.Fatal("lost redemption response succeeded")
	}
	stored, found, err := state.PendingPublisherEnrollmentForSelection(t.Context(), "project", "owner-url:"+url)
	if err != nil || !found || len(stored.ResultJSON) != 0 || string(stored.EnrollmentSecret) != secret {
		t.Fatalf("pending enrollment entered public metadata: %v", err)
	}
	adapter, identity, err := EnsureOwner(t.Context(), state, control, authority, publicURL)
	if err != nil || adapter == nil || identity.GrantId != grant || control.calls != 1 || authority.calls != 2 {
		t.Fatalf("pending owner enrollment did not reuse its key and one-use secret: %v", err)
	}
	if _, _, err := EnsureOwner(t.Context(), state, control, authority, publicURL); err != nil || control.calls != 1 || authority.calls != 2 {
		t.Fatalf("saved owner identity was reenrolled: %v", err)
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

type unusedControl struct{ NativeControl }

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
	url, _ := opaqueid.New(opaqueid.PublicURLPrefix)
	enrollment, _ := opaqueid.New(opaqueid.PublisherEnrollmentPrefix)
	a := &lostEnrollmentResponse{result: authorityv1.PublisherEnrollmentResult{ClientId: id, KeyId: key, GrantId: grant, TeamId: "team", Kind: "saved_public_url", PublicUrlId: &url}}
	if _, _, err := EnrollNative(t.Context(), state, &unusedControl{}, a, enrollment+".secret"); err == nil {
		t.Fatal("lost enrollment response succeeded")
	}
	adapter, result, err := EnrollNative(t.Context(), state, &unusedControl{}, a, enrollment+".secret")
	if err != nil || result.ClientId != id || adapter == nil || a.calls != 2 {
		t.Fatalf("same-key recovery = %+v, %v", result, err)
	}
	if _, _, err := EnrollNative(t.Context(), state, &unusedControl{}, a, enrollment+".secret"); err != nil || a.calls != 2 {
		t.Fatalf("completed enrollment reconsumed its secret: %v", err)
	}
	loaded, result, err := LoadNative(t.Context(), state, &unusedControl{}, a, id)
	if err != nil || loaded == nil || result.GrantId != grant {
		t.Fatalf("saved publisher reuse = %+v, %v", result, err)
	}
	if !loaded.private.Public().(ed25519.PublicKey).Equal(a.public) {
		t.Fatal("stored signing key changed across enrollment retry")
	}
}
