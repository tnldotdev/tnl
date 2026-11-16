package service

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var errConnectorPeerOwnerCapacity = errors.New("connector peer owner capacity exceeded")
var errConnectorPeerRetirement = errors.New("connector peer retirement observation is inconsistent")

func peerDeadline(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// observePeerOwners runs before scheduling delivery work. the exact run's list
// response can retain an installed owner or retire an exact pair. a negative
// fences installation before physical interruption and joins occur unlocked.
func (b *Bound) observePeerOwners(started time.Time, page controlv1.ConnectorPeerPairCandidates) error {
	if started.IsZero() || started.After(time.Now()) || !validPeerCandidates(page, "") {
		return errConnectorPeerRetirement
	}
	b.mu.Lock()
	var retired []*PeerSession
	var preparations []<-chan struct{}
	var result error
	for _, candidate := range page.Items {
		if candidate.Disposition == controlv1.ConnectorPeerPairDispositionRetired {
			p := b.connectorPeers[candidate.PairId]
			if p == nil {
				b.prunePeerOwnersLocked(time.Now())
				if len(b.connectorPeers) >= maxConnectorPeerOwners {
					// the reconciler must fail the run rather than leave a late
					// installation unfenced. no existing owner/fence is evicted.
					b.closed = true
					result = errConnectorPeerOwnerCapacity
					break
				}
				p = b.newPeerOwnerLocked(context.Background(), candidate.PairId)
			}
			observation := candidate.Retirement
			if p.ownerRetired && (!p.retiredAt.Equal(observation.RetiredAt) || !p.retainedUntil.Equal(observation.RetainedUntil)) {
				b.closed = true
				result = errConnectorPeerRetirement
				break
			}
			until := started.Add(observation.RetainedUntil.Sub(observation.ObservedAt))
			if !p.ownerRetired {
				p.ownerRetired = true
				p.retiredAt, p.retainedUntil, p.retirementUntil = observation.RetiredAt, observation.RetainedUntil, until
				if p.replayUntil.IsZero() {
					// keep the same first-stop local replay fence as stop().
					// even an unknown node can have a prior delivery in flight;
					// the mapped server retention is not its local join proof.
					p.replayUntil = time.Now().Add(5 * time.Minute)
				}
			} else {
				// repeated absolute evidence spends time; it never reanchors a
				// retirement or starts another local replay interval.
				p.retirementUntil = peerDeadline(p.retirementUntil, until)
			}
			close(p.changed)
			p.changed = make(chan struct{})
			for a := range p.streams {
				a.retireLocked()
			}
			p.endLocked(tunnel.ConnectorTerminalEnd{Cause: tunnel.ConnectorTerminalOwnerRetired})
			retired = append(retired, p)
			if p.preparationDone != nil {
				preparations = append(preparations, p.preparationDone)
			}
			continue
		}
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
	if result != nil {
		// all entered installations must encounter the run fence, including
		// jobs unrelated to the observation that exhausted local capacity.
		retired, preparations = nil, nil
		for _, p := range b.connectorPeers {
			retired = append(retired, p)
			if p.preparationDone != nil {
				preparations = append(preparations, p.preparationDone)
			}
		}
	}
	b.mu.Unlock()
	for _, p := range retired {
		p.stop()
	}
	for _, p := range retired {
		p.Close()
	}
	for _, done := range preparations {
		<-done
	}
	return result
}

// newPeerOwnerLocked reserves the existing owner slot without starting serving
// work, timers, packet resources, or drain/capacity charges.
func (b *Bound) newPeerOwnerLocked(ctx context.Context, pair string) *PeerSession {
	if b.connectorPeers == nil {
		b.connectorPeers = make(map[string]*PeerSession)
	}
	life, cancel := context.WithCancel(ctx)
	p := &PeerSession{
		bound: b, unbound: true, ctx: life, cancel: cancel,
		identity: peerIdentity{
			pairID: pair, serviceID: b.prepared.Preparation.ServiceId,
			runID: b.prepared.Preparation.ServiceRunId, number: uint64(b.prepared.Preparation.RunNumber),
			publisherID: b.prepared.Preparation.PublisherIdentityId,
		},
		done: make(chan struct{}), changed: make(chan struct{}), ready: make(chan struct{}),
	}
	b.connectorPeers[pair] = p
	return p
}

func (b *Bound) prunePeerOwnersLocked(now time.Time) {
	for id, p := range b.connectorPeers {
		if p.replayUntil.IsZero() || p.replayUntil.After(now) || p.preparationDone != nil ||
			p.retirementUntil.After(now) || p.owner.until.After(now) || p.lease.until.After(now) ||
			p.installedUntil.After(now) || p.pending != nil && p.pending.until.After(now) {
			continue
		}
		select {
		case <-p.done:
			delete(b.connectorPeers, id)
		default:
		}
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
