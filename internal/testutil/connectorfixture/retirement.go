package connectorfixture

import (
	"context"
	"crypto/ed25519"
	"sync"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// Retirement retains only one fixture pair's immutable existing material.
// canonical bytes and request/receipt validation remain with their real owners.
type Retirement struct {
	mu      sync.Mutex
	pair    controlv1.ConnectorPeerPair
	owner   string
	public  ed25519.PublicKey
	key     [32]byte
	receipt *controlv1.ConnectorPeerPairRetirement
	digest  [32]byte
}

func NewRetirement(pair controlv1.ConnectorPeerPair, owner string, public ed25519.PublicKey, sessionKey [32]byte) *Retirement {
	return &Retirement{pair: pair, owner: owner, public: append(ed25519.PublicKey(nil), public...), key: sessionKey}
}

func (r *Retirement) Retire(ctx context.Context, service, pair string, body controlv1.ConnectorPeerPairRetireRequest) (controlv1.ConnectorPeerPairRetirement, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := context.Cause(ctx); err != nil {
		return controlv1.ConnectorPeerPairRetirement{}, err
	}
	proof, err := controlv1.ConnectorPeerPairRetireProof(service, pair, body)
	if err != nil {
		return controlv1.ConnectorPeerPairRetirement{}, err
	}
	mac, signature, err := controlv1.ConnectorPeerPairRetireAuthentication(body)
	if err != nil {
		return controlv1.ConnectorPeerPairRetirement{}, err
	}
	if err := proof.VerifySignature(r.public, mac, signature); err != nil {
		return controlv1.ConnectorPeerPairRetirement{}, err
	}
	if err := proof.VerifySessionProof(r.key[:], mac); err != nil {
		return controlv1.ConnectorPeerPairRetirement{}, err
	}
	digest, err := proof.RequestDigest(mac, signature)
	if err != nil {
		return controlv1.ConnectorPeerPairRetirement{}, err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	receipt := controlv1.ConnectorPeerPairRetirement{
		ServiceId: r.pair.ServiceId, ServiceRunId: r.pair.ServiceRunId, RunNumber: r.pair.RunNumber,
		PublisherIdentityId: r.pair.PublisherIdentityId, PairId: r.pair.PairId, DeliveryId: r.pair.DeliveryId,
		IdempotencyKey: r.owner, Disposition: controlv1.ConnectorPeerPairDispositionRetired, OwnerRevision: 2,
		Retirement: controlv1.ConnectorPeerPairRetirementObservation{
			ObservedAt: now, RetiredAt: now, RetainedUntil: r.pair.ObservedAt.Add(5 * time.Minute),
		},
	}
	if r.receipt != nil {
		if r.digest != digest {
			return controlv1.ConnectorPeerPairRetirement{}, errConnectorFixture
		}
		receipt = *r.receipt
		receipt.Retirement.ObservedAt = now
	}
	if err := receipt.ValidateFor(service, pair, body); err != nil {
		return controlv1.ConnectorPeerPairRetirement{}, err
	}
	r.digest, r.receipt = digest, &receipt
	return receipt, nil
}
