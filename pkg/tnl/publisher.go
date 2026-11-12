package tnl

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

// OIDCAssertion is a transient proof from the application's selected source.
// control verifies its claims and may impose an earlier serving deadline.
type OIDCAssertion struct {
	Token     string
	ExpiresAt time.Time
}

// OIDCSource selects one approved machine identity. Assertion must honor its
// context and return fresh proof; no saved login or publisher file is consulted.
type OIDCSource struct {
	MachineID string
	Assertion func(context.Context) (OIDCAssertion, error)
}

// RegisteredKeySource keeps an explicitly selected source key in the SDK. only
// a reply to native's validated common challenge crosses private IPC.
type RegisteredKeySource struct {
	MachineID  string
	KeyID      string
	PrivateKey ed25519.PrivateKey
}

func (RegisteredKeySource) String() string   { return "private registered identity source" }
func (RegisteredKeySource) GoString() string { return "private registered identity source" }

type registeredApplicationSource struct {
	selection authorityv1.IdentitySourceSelection
	sign      func(context.Context, authorityv1.IdentitySourceChallenge) (string, time.Time, error)
}

// PublisherIdentity holds an explicit source and server, not a native signing key
// or control client. independent invocations get independent native session keys.
type PublisherIdentity struct {
	server     string
	source     OIDCSource
	registered *registeredApplicationSource
}

func (*PublisherIdentity) String() string   { return "prepared application identity source" }
func (*PublisherIdentity) GoString() string { return "prepared application identity source" }

var ErrPublisherScope = publisheridentity.ErrScope
var ErrPublisherSelection = publisheridentity.ErrSelection
var ErrIdentitySourceRequired = errors.New("exactly one explicit OIDC or registered-key identity source is required")

// PreparePublisherIdentity validates an explicit source without acquiring proof.
// it grants no authority; control checks every exchange and refresh.
func PreparePublisherIdentity(ctx context.Context, options Options) (*PublisherIdentity, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	if options.PublisherIdentity != nil || (options.OIDCSource == nil) == (options.RegisteredKeySource == nil) {
		return nil, ErrIdentitySourceRequired
	}
	server, err := naming.CanonicalControlURL(options.ServerURL)
	if err != nil || server != options.ServerURL {
		return nil, ErrPublisherScope
	}
	if options.RegisteredKeySource != nil {
		source := options.RegisteredKeySource
		selection := authorityv1.IdentitySourceSelection{Kind: "registered_key", MachineId: source.MachineID, KeyId: source.KeyID}
		if !machineproof.ValidSource(selection) || len(source.PrivateKey) != ed25519.PrivateKeySize || !ed25519.NewKeyFromSeed(source.PrivateKey[:32]).Equal(source.PrivateKey) {
			return nil, ErrIdentitySourceRequired
		}
		private := append(ed25519.PrivateKey(nil), source.PrivateKey...)
		registered := &registeredApplicationSource{selection: selection}
		registered.sign = func(ctx context.Context, challenge authorityv1.IdentitySourceChallenge) (string, time.Time, error) {
			if err := context.Cause(ctx); err != nil {
				return "", time.Time{}, err
			}
			now := time.Now()
			assertion, err := publisherproof.Sign(selection.MachineId, selection.KeyId, challenge.Scope, challenge.Audience, private, now)
			return assertion, time.Unix(now.Unix(), 0).Add(publisherproof.AssertionLifetime), errors.Join(context.Cause(ctx), err)
		}
		return &PublisherIdentity{server: server, registered: registered}, nil
	}
	source := *options.OIDCSource
	if !opaqueid.Valid(source.MachineID, "mci_") || source.Assertion == nil {
		return nil, ErrIdentitySourceRequired
	}
	return &PublisherIdentity{server: server, source: source}, nil
}

func applicationIdentity(ctx context.Context, options Options) (*PublisherIdentity, error) {
	if options.PublisherIdentity == nil {
		return PreparePublisherIdentity(ctx, options)
	}
	identity := options.PublisherIdentity
	if options.OIDCSource != nil || options.RegisteredKeySource != nil || identity.server == "" || (identity.source.Assertion == nil && identity.registered == nil) || options.ServerURL != "" && options.ServerURL != identity.server {
		return nil, ErrPublisherSelection
	}
	return identity, nil
}
