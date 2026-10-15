package native

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type lostEnrollmentResponse struct {
	result authorityv1.PublisherEnrollmentResult
	public ed25519.PublicKey
	calls  int
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
	control := &ownerEnrollmentControl{enrollment: controlv1.PublisherEnrollment{Id: enrollment, TeamId: "team", Kind: "saved_url", PublicUrlId: &url, EnrollmentKey: secret}}
	authority := &lostEnrollmentResponse{result: authorityv1.PublisherEnrollmentResult{ClientId: id, KeyId: key, GrantId: grant, TeamId: "team", Kind: "saved_url", PublicUrlId: &url}}
	route := controlv1.PublicURL{Id: url, TeamId: "team", CanonicalHostname: "oauth.example", Purpose: controlv1.Oauth, LifecycleState: controlv1.Enabled}
	if _, _, err := EnsureOwner(t.Context(), state, control, authority, route); err == nil {
		t.Fatal("lost redemption response succeeded")
	}
	stored, found, err := state.PublisherSigningIdentity(t.Context(), "owner-url:"+url)
	if err != nil || !found || string(stored.PublicValue) != "{}" {
		t.Fatalf("pending enrollment entered public metadata: %v", err)
	}
	adapter, identity, err := EnsureOwner(t.Context(), state, control, authority, route)
	if err != nil || adapter == nil || identity.GrantId != grant || control.calls != 1 || authority.calls != 2 {
		t.Fatalf("pending owner enrollment did not reuse its key and one-use secret: %v", err)
	}
	if _, _, err := EnsureOwner(t.Context(), state, control, authority, route); err != nil || control.calls != 1 || authority.calls != 2 {
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
	a := &lostEnrollmentResponse{result: authorityv1.PublisherEnrollmentResult{ClientId: id, KeyId: key, GrantId: grant, TeamId: "team", Kind: "saved_url", PublicUrlId: &url}}
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
