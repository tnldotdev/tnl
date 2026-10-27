package relay

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// the old deadline remains authoritative while control checks a renewal. expiry
// marks this owner stopped before canceling, so a late success cannot revive it.
func (d *nativePairDelivery) watchAuthority(a *NativeConnectorAcceptor) {
	defer close(d.authorityDone)
	for {
		d.mu.Lock()
		until, changed := d.deadline, d.changed
		expired := d.closed || !until.After(a.now())
		if expired {
			d.closed = true
		}
		d.mu.Unlock()
		if expired {
			d.cancel()
			return
		}
		timer := time.NewTimer(until.Sub(a.now()))
		select {
		case <-d.ctx.Done():
			timer.Stop()
			return
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (d *nativePairDelivery) renewClaim(ctx context.Context, a *NativeConnectorAcceptor, transport muxsession.Session, proof tunnelv1.NativePairLegProof, initial nativeConnectorClaim) (tunnelv1.NativePairLegAccepted, error) {
	denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	d.mu.Lock()
	until, closed := d.deadline, d.closed
	d.mu.Unlock()
	if closed || d.ctx.Err() != nil || !until.After(a.now()) {
		return tunnelv1.NativePairLegAccepted{}, denied
	}
	call, cancel := context.WithTimeout(ctx, min(2*time.Second, until.Sub(a.now())))
	defer cancel()
	next, err := a.claim(call, transport, proof)
	if err != nil {
		if d.ctx.Err() == nil && isRetryableControlError(err) {
			return tunnelv1.NativePairLegAccepted{}, &tunnel.ProtocolError{Code: tunnelv1.Unavailable}
		}
		return tunnelv1.NativePairLegAccepted{}, errors.Join(err, denied)
	}
	if next.ref != initial.ref || next.key != initial.key || next.receipt.PairID != initial.receipt.PairID || next.receipt.DeliveryID != initial.receipt.DeliveryID ||
		next.receipt.DeliveryGeneration != initial.receipt.DeliveryGeneration || next.receipt.ConnectionSlot != initial.receipt.ConnectionSlot || next.receipt.SourceIP != initial.receipt.SourceIP {
		return tunnelv1.NativePairLegAccepted{}, denied
	}
	lease, valid := a.currentLease(proof, a.now())
	current, present := a.Publishers.nativeCandidate(initial.ref, lease, a.now())
	if !valid || !present || current != d.connection {
		return tunnelv1.NativePairLegAccepted{}, denied
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.ctx.Err() != nil || !d.deadline.After(a.now()) || !next.receipt.ExpiresAt.After(a.now()) {
		return tunnelv1.NativePairLegAccepted{}, denied
	}
	d.deadline = next.receipt.ExpiresAt
	close(d.changed)
	d.changed = make(chan struct{})
	return next.receipt, nil
}
