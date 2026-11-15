package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	processidentity "github.com/tnldotdev/tnl/internal/publisher/processidentity"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

var ErrScope = errors.New("publisher operation is outside the selected grant")

type AssertionExchanger interface {
	ExchangePublisherAssertion(context.Context, string, string, string, ed25519.PrivateKey) (string, error)
}

// NativeControl supplies explicit capabilities for the selected operation.
// every native publisher requires Services; deployed owners also supply Runtime.
type NativeControl struct {
	Services    ServiceControl
	Allocations ServiceAllocationControl
	Runtime     processidentity.Control
}

// Native is the single grant-scoped adapter for CLI, app, SDK, and guest
// entrypoints. construct one per selected service worker; it owns no local database.
type Native struct {
	NativeControl
	authority            AssertionExchanger
	identity             nativeScope
	selectedServiceID    string
	allocationInvocation string
	allocatedServiceID   string
	allocationFinished   bool
	deploymentAllocation *deploymentAllocation
	private              ed25519.PrivateKey
	traffic              *trafficlimits.Selection
	runtime              *processidentity.Owner
}

func NewNative(control NativeControl, authority AssertionExchanger, identity authorityv1.PublisherEnrollmentResult, private ed25519.PrivateKey) (*Native, error) {
	scope, err := newNativeScope(identity)
	if err != nil {
		return nil, err
	}
	return newNative(control, authority, scope, private)
}

func newNative(control NativeControl, authority AssertionExchanger, scope nativeScope, private ed25519.PrivateKey) (*Native, error) {
	if authority == nil || !validSigningKey(private) || control.Services == nil {
		return nil, ErrScope
	}
	n := &Native{NativeControl: control, authority: authority, identity: scope, selectedServiceID: scope.serviceID, private: append(ed25519.PrivateKey(nil), private...)}
	server, err := naming.CanonicalControlURL(n.ControlURL())
	if err != nil || server != n.ControlURL() {
		return nil, ErrScope
	}
	return n, nil
}

func validSigningKey(private ed25519.PrivateKey) bool {
	return len(private) == ed25519.PrivateKeySize && bytes.Equal(ed25519.NewKeyFromSeed(private.Seed()), private)
}

func (n *Native) Access(ctx context.Context) (string, error) {
	if n.identity.guestID != "" {
		if !n.identity.expiresAt.After(time.Now()) {
			return "", ErrScope
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, n.identity.expiresAt)
		defer cancel()
	}
	return n.authority.ExchangePublisherAssertion(ctx, n.identity.clientID, n.identity.grantID, n.identity.keyID, append(ed25519.PrivateKey(nil), n.private...))
}

func (n *Native) PublisherIdentityID() string {
	if n == nil {
		return ""
	}
	return n.identity.clientID
}

func (n *Native) PublisherGrantID() string { return n.identity.grantID }
func (n *Native) PublisherKeyID() string   { return n.identity.keyID }
