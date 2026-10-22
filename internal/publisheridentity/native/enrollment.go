package native

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

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
// lock. a locally issued one-use secret remains protected until promotion;
// access tokens do not enter client state.
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
	secretDigest := sha256.Sum256([]byte(secret))
	if installed, found, err := state.SelectedPublisherIdentity(ctx, "enrollment", hex.EncodeToString(secretDigest[:])); err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, err
	} else if found {
		var identity authorityv1.PublisherEnrollmentResult
		if json.Unmarshal(installed.PublicDocument, &identity) != nil || identity.ClientId != installed.ID {
			return nil, identity, ErrScope
		}
		native, err := NewNative(control, authority, identity, installed.SigningKey)
		return native, identity, err
	}
	saved, found, err := state.PendingPublisherEnrollment(ctx, p[0])
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, err
	}
	if !found {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, authorityv1.PublisherEnrollmentResult{}, err
		}
		saved = clientstate.PendingPublisherEnrollment{
			EnrollmentID: p[0], SelectionKind: "explicit", SelectionKey: p[0],
			PublicKey: public, SigningKey: private, EnrollmentSecret: []byte(secret),
			ExpiresAt: time.Now().Add(10 * time.Minute),
		}
		if err := state.SavePendingPublisherEnrollment(ctx, saved); err != nil {
			return nil, authorityv1.PublisherEnrollmentResult{}, err
		}
	}
	private := ed25519.PrivateKey(saved.SigningKey)
	if !validSigningKey(private) || !bytes.Equal(private.Public().(ed25519.PublicKey), saved.PublicKey) || !saved.ExpiresAt.After(time.Now()) || len(saved.EnrollmentSecret) != 0 && !bytes.Equal(saved.EnrollmentSecret, []byte(secret)) {
		return nil, authorityv1.PublisherEnrollmentResult{}, ErrScope
	}
	var identity authorityv1.PublisherEnrollmentResult
	if len(saved.ResultJSON) != 0 {
		if json.Unmarshal(saved.ResultJSON, &identity) != nil {
			return nil, identity, ErrScope
		}
	} else {
		identity, err = authority.RedeemPublisherEnrollment(ctx, secret, private.Public().(ed25519.PublicKey))
		if err != nil {
			return nil, identity, err
		}
		saved.ResultJSON, err = json.Marshal(identity)
		if err != nil {
			return nil, identity, err
		}
	}
	native, err := NewNative(control, authority, identity, private)
	if err != nil {
		return nil, identity, err
	}
	if err := state.RecordPublisherEnrollmentResult(ctx, saved.EnrollmentID, saved.ResultJSON); err != nil {
		return nil, identity, err
	}
	if err := state.PromotePublisherEnrollment(ctx, saved.EnrollmentID, clientstate.PublisherIdentity{ID: identity.ClientId, PublicDocument: saved.ResultJSON, SigningKey: private}); err != nil {
		return nil, identity, err
	}
	return native, identity, nil
}

func LoadNative(ctx context.Context, state *clientstate.Store, control NativeControl, authority AssertionExchanger, publisherID string) (*Native, authorityv1.PublisherEnrollmentResult, error) {
	if !opaqueid.Valid(publisherID, opaqueid.PublisherIdentityPrefix) {
		return nil, authorityv1.PublisherEnrollmentResult{}, ErrScope
	}
	saved, found, err := state.PublisherIdentity(ctx, publisherID)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, err
	}
	if !found {
		return nil, authorityv1.PublisherEnrollmentResult{}, ErrScope
	}
	var identity authorityv1.PublisherEnrollmentResult
	if json.Unmarshal(saved.PublicDocument, &identity) != nil || identity.ClientId != publisherID || saved.ID != publisherID {
		return nil, identity, ErrScope
	}
	native, err := NewNative(control, authority, identity, saved.SigningKey)
	return native, identity, err
}

// savePendingEnrollment gives a locally issued enrollment its own explicit
// secret and signing-key fields before the first redemption can leave process.
func savePendingEnrollment(ctx context.Context, state *clientstate.Store, kind, key string, enrollmentID, secret string) (clientstate.PendingPublisherEnrollment, error) {
	if !opaqueid.Valid(enrollmentID, opaqueid.PublisherEnrollmentPrefix) || !strings.HasPrefix(secret, enrollmentID+".") || len(secret) > 256 {
		return clientstate.PendingPublisherEnrollment{}, ErrScope
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return clientstate.PendingPublisherEnrollment{}, err
	}
	pending := clientstate.PendingPublisherEnrollment{EnrollmentID: enrollmentID, SelectionKind: kind, SelectionKey: key, PublicKey: public, SigningKey: private, EnrollmentSecret: []byte(secret), ExpiresAt: time.Now().Add(10 * time.Minute)}
	return pending, state.SavePendingPublisherEnrollment(ctx, pending)
}
