package controlv1

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// ConnectorPeerPairRetireProof adapts generated scope to the sole handwritten
// proof. callers may construct the MAC and signature after validating this scope.
func ConnectorPeerPairRetireProof(serviceID, pairID string, body ConnectorPeerPairRetireRequest) (tunnelv1.ConnectorPeerPairRetireProof, error) {
	proof := tunnelv1.ConnectorPeerPairRetireProof{ServiceID: serviceID, PairID: pairID,
		ServiceRunID: body.ServiceRunId, RunNumber: body.RunNumber, PublisherIdentityID: body.PublisherIdentityId,
		DeliveryID: body.DeliveryId, IdempotencyKey: body.IdempotencyKey, RequestedAt: body.RequestedAt}
	if _, err := proof.Message(make([]byte, sha256.Size)); err != nil {
		return tunnelv1.ConnectorPeerPairRetireProof{}, err
	}
	return proof, nil
}

// ConnectorPeerPairRetireAuthentication strictly decodes the two existing-key
// proofs. it does not authenticate either key or define another signing format.
func ConnectorPeerPairRetireAuthentication(body ConnectorPeerPairRetireRequest) (sessionProof, signature []byte, err error) {
	decode := func(value string, size int) ([]byte, error) {
		if len(value) != base64.RawURLEncoding.EncodedLen(size) {
			return nil, tunnelv1.ErrConnectorPeerPairRetireProof
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
		if err != nil || len(raw) != size || base64.RawURLEncoding.EncodeToString(raw) != value {
			return nil, tunnelv1.ErrConnectorPeerPairRetireProof
		}
		return raw, nil
	}
	sessionProof, err = decode(body.SessionProof, sha256.Size)
	if err != nil {
		return nil, nil, err
	}
	signature, err = decode(body.Signature, ed25519.SignatureSize)
	if err != nil {
		return nil, nil, err
	}
	return sessionProof, signature, nil
}

// Validate checks a negative observation, never a positive owner lease.
func (o ConnectorPeerPairRetirementObservation) Validate() error {
	if o.ObservedAt.IsZero() || o.RetiredAt.IsZero() || o.RetainedUntil.IsZero() ||
		o.RetiredAt.After(o.ObservedAt) || !o.RetainedUntil.After(o.ObservedAt) ||
		o.RetainedUntil.Sub(o.RetiredAt) > 5*time.Minute+5*time.Second {
		return tunnelv1.ErrConnectorPeerPairRetireProof
	}
	return nil
}

// ValidateFor matches a committed retirement receipt to its exact request.
// the generated disposition enum is the only HTTP wire-state definition.
func (r ConnectorPeerPairRetirement) ValidateFor(serviceID, pairID string, body ConnectorPeerPairRetireRequest) error {
	if _, err := ConnectorPeerPairRetireProof(serviceID, pairID, body); err != nil {
		return err
	}
	if r.ServiceId != serviceID || r.PairId != pairID || r.ServiceRunId != body.ServiceRunId || r.RunNumber != body.RunNumber ||
		r.PublisherIdentityId != body.PublisherIdentityId || r.DeliveryId != body.DeliveryId || r.IdempotencyKey != body.IdempotencyKey ||
		r.Disposition != ConnectorPeerPairDispositionRetired || r.OwnerRevision != 2 {
		return tunnelv1.ErrConnectorPeerPairRetireProof
	}
	return r.Retirement.Validate()
}
