package stream

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/peer"
)

var errPeerHandoffConsumed = errors.New("native carrier handoff attempt was consumed")

type peerLegPredecessor struct {
	nonce  [32]byte
	source string
	until  time.Time
}

// a failed packet carrier retires the associated control owner as well. otherwise
// a live control stream could keep renewing an unusable packet registration.
type peerRelayCarrier struct {
	peer.Carrier
	stop context.CancelFunc
}

var _ peer.Carrier = (*peerRelayCarrier)(nil)

func (c *peerRelayCarrier) Send(ctx context.Context, frame []byte) error {
	err := c.Carrier.Send(ctx, frame)
	if err != nil {
		c.stop()
	}
	return err
}

func (c *peerRelayCarrier) Receive(ctx context.Context) ([]byte, error) {
	frame, err := c.Carrier.Receive(ctx)
	if err != nil {
		c.stop()
	}
	return frame, err
}

func (c *peerRelayCarrier) Close() error {
	c.stop()
	return c.Carrier.Close()
}

// maintainRelayLeg owns this slot's renewal and reconnect work. replacement
// touches neither the inner QUIC connection nor any application stream. only
// failures before handoff may retry, within the predecessor's fixed deadline.
func (p *peerConnection) maintainRelayLeg(config Config, slot int) {
	leg := p.legs[slot]
	defer func() { leg.Close() }()
	for {
		renewed := make(chan struct{})
		go func() {
			defer close(renewed)
			leg.renewPrepared(p.prepared, p.initial, p.signer, slot)
		}()
		select {
		case <-p.ctx.Done():
		case <-leg.ctx.Done():
		}
		leg.Close()
		<-renewed
		if p.ctx.Err() != nil {
			return
		}
		leg.mu.Lock()
		previous := peerLegPredecessor{nonce: leg.nonce, source: leg.receipt.SourceIP, until: leg.until}
		leg.mu.Unlock()
		_ = p.paths[slot].Install(nil)
		for {
			if p.ctx.Err() != nil || !previous.until.After(time.Now()) {
				return
			}
			binding, err := p.prepared.peerCurrent()
			if err == nil && !samePeerDelivery(p.initial, binding) {
				return
			}
			if err == nil {
				call, cancel := context.WithTimeout(p.ctx, min(5*time.Second, time.Until(previous.until)))
				next, err := racePeerRelayLeg(call, p.ctx, config, p.socket, binding, p.signer, slot, &previous)
				cancel()
				if err == nil {
					leg = next
					p.legs[slot] = next
					if p.paths[slot].Install(next.carrier) != nil {
						return
					}
					break
				}
				if errors.Is(err, errPeerHandoffConsumed) {
					return
				}
			}
			timer := time.NewTimer(min(250*time.Millisecond, time.Until(previous.until)))
			select {
			case <-p.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
}
