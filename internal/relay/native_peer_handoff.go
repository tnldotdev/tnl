package relay

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const maxNativeCarrierCandidates = 64

// nativePairBridge owns the publisher registration across connector socket loss.
// its deadline and replay state survive detachment; only a current signed claim
// and an exact predecessor handoff can install another connector carrier.
type nativePairBridge struct {
	owner     *nativePacketSession
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	publisher peer.Carrier
	connector *peer.CarrierSlot
	claim     nativeConnectorClaim
	proof     tunnelv1.NativePairLegProof
	mu        sync.Mutex
	active    *nativePairDelivery
	nonce     []byte
	used      map[[32]byte]struct{}
	deadline  time.Time
}

func (*nativePairBridge) String() string   { return "native pair packet bridge" }
func (*nativePairBridge) GoString() string { return "native pair packet bridge" }

func (p *nativePacketSession) selectNativeBridge(ctx context.Context, a *NativeConnectorAcceptor, d *nativePairDelivery, proof tunnelv1.NativePairLegProof, claim nativeConnectorClaim, id [16]byte, selection tunnelv1.NativeLegBinding) (*nativePairBridge, error) {
	denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	if !selection.Matches(proof) {
		return nil, denied
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ctx.Err() != nil || ctx.Err() != nil {
		return nil, errors.Join(denied, context.Cause(ctx), net.ErrClosed)
	}
	b := p.bridges[id]
	nonce := [32]byte(selection.Nonce)
	if len(selection.PreviousNonce) != 0 {
		if b == nil {
			return nil, denied
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if _, spent := b.used[nonce]; spent {
			return nil, denied
		}
		if len(b.used) >= maxNativeCarrierCandidates {
			return nil, &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
		}
		if b.ctx.Err() != nil || !b.deadline.After(a.now()) || !bytes.Equal(b.nonce, selection.PreviousNonce) ||
			!b.proof.SameLeg(proof) || b.claim.key != claim.key || b.claim.ref != claim.ref || b.claim.receipt.SourceIP != claim.receipt.SourceIP {
			return nil, denied
		}
		// selection transfers delivery, not serving time. renewal on the selected
		// control stream can later install freshly checked authority.
		until := b.deadline
		if d.deadline.Before(until) {
			until = d.deadline
		}
		if !until.After(a.now()) || ctx.Err() != nil {
			return nil, denied
		}
		old := b.active
		b.nonce, b.active, b.deadline = bytes.Clone(selection.Nonce), d, until
		b.used[nonce] = struct{}{}
		d.deadline = until
		close(d.changed)
		d.changed = make(chan struct{})
		if err := b.connector.Install(&nativeReadyCarrier{Carrier: d.towardConnector, stop: d.cancel}); err != nil {
			b.cancel()
			return nil, errors.Join(denied, err)
		}
		if old != nil {
			old.cancel()
		}
		return b, nil
	}
	if b != nil {
		return nil, denied
	}
	if len(p.bridges) >= defaultNativeConnectorSessions {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
	}
	binding := peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: id, Generation: uint64(claim.receipt.DeliveryGeneration)},
		Key: claim.key, Kind: peer.NativePeer, Path: uint8(claim.receipt.ConnectionSlot), Role: 0}
	published, err := p.register(ctx, binding, true)
	if err != nil {
		return nil, errors.Join(&tunnel.ProtocolError{Code: tunnelv1.Unavailable}, err)
	}
	life, cancel := context.WithCancel(p.ctx)
	b = &nativePairBridge{owner: p, ctx: life, cancel: cancel, done: make(chan struct{}), publisher: published,
		connector: peer.NewCarrierSlot(), claim: claim, proof: proof, active: d, nonce: bytes.Clone(selection.Nonce),
		used: map[[32]byte]struct{}{nonce: {}}, deadline: d.deadline}
	_ = b.connector.Install(&nativeReadyCarrier{Carrier: d.towardConnector, stop: d.cancel})
	p.bridges[id] = b
	go b.serve(a, d.connection, id)
	return b, nil
}

func (b *nativePairBridge) detach(d *nativePairDelivery) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active == d {
		b.active = nil
		_ = b.connector.Install(nil)
	}
}

func (b *nativePairBridge) renew(d *nativePairDelivery, until, now time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active != d || b.ctx.Err() != nil || !b.deadline.After(now) || !until.After(now) {
		return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	}
	b.deadline = until
	return nil
}

func (b *nativePairBridge) serve(a *NativeConnectorAcceptor, connection *serviceConnection, id [16]byte) {
	defer close(b.done)
	var workers sync.WaitGroup
	finished := make(chan error, 2)
	ready := make(chan struct{})
	workers.Go(func() {
		finished <- forwardNativePackets(b.ctx, peer.RetainCarrierReplay(b.connector), b.publisher, ready)
	})
	workers.Go(func() {
		select {
		case <-ready:
			finished <- forwardNativePackets(b.ctx, b.publisher, b.connector, nil)
		case <-b.ctx.Done():
			finished <- b.ctx.Err()
		}
	})
	defer func() {
		b.cancel()
		b.mu.Lock()
		if b.active != nil {
			b.active.cancel()
		}
		b.mu.Unlock()
		_ = b.connector.Close()
		_ = b.publisher.Close()
		workers.Wait()
		b.owner.mu.Lock()
		delete(b.owner.bridges, id)
		b.owner.mu.Unlock()
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		b.mu.Lock()
		until := b.deadline
		expired := !until.After(a.now())
		if expired {
			b.cancel()
		}
		b.mu.Unlock()
		if expired {
			return
		}
		timer := time.NewTimer(until.Sub(a.now()))
		select {
		case <-b.ctx.Done():
			timer.Stop()
			return
		case <-finished:
			timer.Stop()
			return
		case <-timer.C:
		case <-ticker.C:
			timer.Stop()
			lease, valid := a.currentLease(b.proof, a.now())
			if current, ok := a.Publishers.nativeCandidate(b.claim.ref, lease, a.now()); !valid || !ok || current != connection {
				return
			}
		}
	}
}

// publisher probes may arrive before a replacement TLS carrier introduces its
// framed stream. drop those packets until the connector sends its first frame;
// inner QUIC retransmits without repeating an application admission.
type nativeReadyCarrier struct {
	peer.Carrier
	ready atomic.Bool
	stop  context.CancelFunc
}

var _ peer.Carrier = (*nativeReadyCarrier)(nil)

func (c *nativeReadyCarrier) Send(ctx context.Context, frame []byte) error {
	if !c.ready.Load() {
		return ctx.Err()
	}
	err := c.Carrier.Send(ctx, frame)
	if err != nil {
		c.stop()
	}
	return err
}

func (c *nativeReadyCarrier) Receive(ctx context.Context) ([]byte, error) {
	frame, err := c.Carrier.Receive(ctx)
	if err == nil {
		c.ready.Store(true)
	} else {
		c.stop()
	}
	return frame, err
}

func (c *nativeReadyCarrier) Close() error {
	c.stop()
	return c.Carrier.Close()
}
