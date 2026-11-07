package service

import (
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func peerDeadline(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// observePeerOwners runs before scheduling delivery work. the exact run's list
// response can retain an installed owner during relay loss, but cannot create an
// owner, revive one locally expired, or renew packet or application permission.
func (b *Bound) observePeerOwners(started time.Time, page controlv1.ConnectorPeerPairCandidates) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, candidate := range page.Items {
		observation := candidate.OwnerAuthority
		p := b.connectorPeers[candidate.PairId]
		if observation == nil || p == nil || !p.currentLocked() {
			continue
		}
		duration := observation.ExpiresAt.Sub(observation.ObservedAt)
		if started.IsZero() || started.After(time.Now()) || observation.ObservedAt.IsZero() || duration <= 0 || duration > 5*time.Minute {
			continue
		}
		p.observeOwnerLocked(peerLease{until: started.Add(duration), authorityUntil: observation.ExpiresAt, observedAt: observation.ObservedAt})
	}
}

// an unchanged absolute expiry must never acquire a later monotonic deadline
// merely because the same evidence arrived in a later RPC. older observations
// cannot undo a newer one; a shorter bound can only narrow current authority.
func (p *PeerSession) observeOwnerLocked(next peerLease) {
	if !p.currentLocked() || !next.until.After(time.Now()) || !next.observedAt.After(p.owner.observedAt) {
		return
	}
	if !next.authorityUntil.After(p.owner.authorityUntil) {
		next.until = peerDeadline(next.until, p.owner.until)
	}
	p.owner = next
	close(p.changed)
	p.changed = make(chan struct{})
}
