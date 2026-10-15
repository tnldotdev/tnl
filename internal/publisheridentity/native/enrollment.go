package native

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

type EnrollmentAuthority interface {
	AssertionExchanger
	RedeemPublisherEnrollment(context.Context, string, ed25519.PublicKey) (authorityv1.PublisherEnrollmentResult, error)
}

// EnrollNative durably saves the locally generated key before redeeming a
// one-use secret. a lost response retries with that exact key under a local
// lock. neither the enrollment secret nor access tokens enter client state.
func EnrollNative(ctx context.Context, state *clientstate.Store, control NativeControl, authority EnrollmentAuthority, secret string) (*Native, authorityv1.PublisherEnrollmentResult, error) {
	if state == nil || control == nil || authority == nil || len(secret) > 256 {
		return nil, authorityv1.PublisherEnrollmentResult{}, ErrScope
	}
	p := strings.Split(secret, ".")
	if len(p) != 2 || !opaqueid.Valid(p[0], opaqueid.PublisherEnrollmentPrefix) {
		return nil, authorityv1.PublisherEnrollmentResult{}, ErrScope
	}
	scope := "enrollment:" + p[0]
	lock, err := state.LockPublisherSigningIdentity(ctx, scope)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, err
	}
	defer lock.Close()
	saved, found, err := state.PublisherSigningIdentity(ctx, scope)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, err
	}
	if !found {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, authorityv1.PublisherEnrollmentResult{}, err
		}
		saved = clientstate.PublisherSigningIdentity{ID: p[0], PublicValue: []byte("{}"), PrivateValue: private}
		if err := state.SavePublisherSigningIdentity(ctx, scope, saved); err != nil {
			return nil, authorityv1.PublisherEnrollmentResult{}, err
		}
	}
	if len(saved.PrivateValue) != ed25519.PrivateKeySize {
		return nil, authorityv1.PublisherEnrollmentResult{}, ErrScope
	}
	var identity authorityv1.PublisherEnrollmentResult
	if json.Unmarshal(saved.PublicValue, &identity) != nil {
		return nil, identity, ErrScope
	}
	if identity.ClientId != "" {
		current, found, err := state.PublisherSigningIdentity(ctx, "publisher:"+identity.ClientId)
		if err != nil {
			return nil, identity, err
		}
		if found {
			if json.Unmarshal(current.PublicValue, &identity) != nil || identity.ClientId != current.ID {
				return nil, identity, ErrScope
			}
			saved = current
		}
	}
	private := ed25519.PrivateKey(saved.PrivateValue)
	if identity.ClientId == "" {
		identity, err = authority.RedeemPublisherEnrollment(ctx, secret, private.Public().(ed25519.PublicKey))
		if err != nil {
			return nil, identity, err
		}
		if _, err := NewNative(control, authority, identity, private); err != nil {
			return nil, identity, err
		}
		saved.ID = identity.ClientId
		saved.PublicValue, err = json.Marshal(identity)
		if err != nil {
			return nil, identity, err
		}
		if err := state.SavePublisherSigningIdentity(ctx, scope, saved); err != nil {
			return nil, identity, err
		}
	}
	if err := state.SavePublisherSigningIdentity(ctx, "publisher:"+identity.ClientId, saved); err != nil {
		return nil, identity, err
	}
	native, err := NewNative(control, authority, identity, private)
	return native, identity, err
}

func LoadNative(ctx context.Context, state *clientstate.Store, control NativeControl, authority AssertionExchanger, publisherID string) (*Native, authorityv1.PublisherEnrollmentResult, error) {
	if !opaqueid.Valid(publisherID, opaqueid.PublisherIdentityPrefix) {
		return nil, authorityv1.PublisherEnrollmentResult{}, ErrScope
	}
	saved, found, err := state.PublisherSigningIdentity(ctx, "publisher:"+publisherID)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, err
	}
	if !found {
		return nil, authorityv1.PublisherEnrollmentResult{}, ErrScope
	}
	var identity authorityv1.PublisherEnrollmentResult
	if json.Unmarshal(saved.PublicValue, &identity) != nil || identity.ClientId != publisherID || saved.ID != publisherID {
		return nil, identity, ErrScope
	}
	native, err := NewNative(control, authority, identity, saved.PrivateValue)
	return native, identity, err
}
