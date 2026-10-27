package stream

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func (l *peerRelayLeg) watchAuthority() {
	for {
		l.mu.Lock()
		until, changed := l.until, l.changed
		expired := l.retired || !until.After(time.Now())
		if expired {
			l.retired = true
			l.cancel()
		}
		l.mu.Unlock()
		if expired {
			return
		}
		timer := time.NewTimer(time.Until(until))
		select {
		case <-l.ctx.Done():
			timer.Stop()
			return
		case <-l.session.Done():
			timer.Stop()
			return
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (l *peerRelayLeg) renewPrepared(prepared *preparedSelection, initial preparedPeer, signer Signer, slot int) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-ticker.C:
		}
		l.mu.Lock()
		until := l.until
		l.mu.Unlock()
		if time.Until(until) > 15*time.Second {
			continue
		}
		binding, err := prepared.peerCurrent()
		if err != nil {
			continue
		} // retain only the old confirmed claim deadline.
		if !samePeerDelivery(initial, binding) {
			l.cancel()
			return
		}
		if !binding.expiresAt.After(until.Add(time.Second)) {
			continue
		}
		proof, err := newPeerLegProof(binding, signer, slot)
		if err != nil {
			l.cancel()
			return
		}
		request, err := opaqueid.New(opaqueid.RequestPrefix)
		if err != nil {
			l.cancel()
			return
		}
		started := time.Now()
		call, cancel := context.WithTimeout(l.ctx, min(2*time.Second, time.Until(until)))
		receipt, err := l.session.RenewNativeLeg(call, request, proof, l.receipt)
		cancel()
		if err != nil {
			var protocol *tunnel.ProtocolError
			if errors.As(err, &protocol) && protocol != nil && protocol.Code == tunnelv1.Unavailable {
				continue
			}
			l.cancel()
			return
		}
		next := minSelectionTime(binding.expiresAt, started.Add(receipt.ExpiresAt.Sub(receipt.ObservedAt)))
		l.mu.Lock()
		if l.retired || l.ctx.Err() != nil || !l.until.After(time.Now()) || !next.After(time.Now()) {
			l.mu.Unlock()
			l.cancel()
			return
		}
		l.until = next
		close(l.changed)
		l.changed = make(chan struct{})
		l.mu.Unlock()
	}
}
