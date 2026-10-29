package relay

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// nativePacketSession keeps publisher registrations through connector socket
// replacement. it owns no application admission or visitor permission.
type nativePacketSession struct {
	*peer.SharedSession
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	closed  bool
	bridges map[[16]byte]*nativeBridge
	once    sync.Once
}

func newNativePacketSession(parent context.Context, outer muxsession.Session) (*nativePacketSession, error) {
	ctx, cancel := context.WithCancel(parent)
	packets, err := peer.NewSharedSession(ctx, outer)
	if err != nil {
		cancel()
		return nil, err
	}
	return &nativePacketSession{SharedSession: packets, ctx: ctx, cancel: cancel, bridges: make(map[[16]byte]*nativeBridge)}, nil
}

func (p *nativePacketSession) Close() {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		bridges := make([]*nativeBridge, 0, len(p.bridges))
		for _, bridge := range p.bridges {
			bridges = append(bridges, bridge)
		}
		p.mu.Unlock()
		p.cancel()
		_ = p.SharedSession.Close()
		for _, bridge := range bridges {
			<-bridge.done
		}
	})
}

func (r *ServiceRegistry) nativeCandidate(ref tunnelv1.ServicePublisherConnectionRef, lease relayv1.RelayLease) (*serviceConnection, bool) {
	if ref.Validate() != nil || lease.Draining || !lease.LeaseExpiresAt.After(time.Now()) || ref.RelayServiceID != lease.RelayServiceId {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.connections[ref.PublisherConnectionID]
	if r.closed || c == nil || c.ref != ref || c.packets == nil || c.lease.RelayServiceId != lease.RelayServiceId || c.lease.RelayId != lease.RelayId || c.lease.RelayRunId != lease.RelayRunId || c.lease.RelayLeaseRevision != lease.RelayLeaseRevision {
		return nil, false
	}
	c.paths.mu.Lock()
	defer c.paths.mu.Unlock()
	return c, c.paths.stateErrorLocked() == nil
}

func peerBinding(claim nativeConnectorClaim, id [16]byte, role uint8) peer.PairBinding {
	return peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: id, Generation: uint64(claim.receipt.DeliveryGeneration)}, Key: claim.key, Path: uint8(claim.receipt.ConnectionSlot), Role: role}
}

type nativeDelivery struct {
	ctx        context.Context
	cancel     context.CancelFunc
	claim      nativeConnectorClaim
	proof      tunnelv1.NativePairLegProof
	connection *serviceConnection
	carrier    peer.Carrier
	mu         sync.Mutex
	until      time.Time
	changed    chan struct{}
	bridge     *nativeBridge
}

func (d *nativeDelivery) watch(a *NativeConnectorAcceptor) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	defer d.cancel()
	for {
		d.mu.Lock()
		until, changed := d.until, d.changed
		expired := !until.After(time.Now())
		if expired {
			d.cancel()
		}
		d.mu.Unlock()
		if expired {
			return
		}
		timer := time.NewTimer(time.Until(until))
		select {
		case <-d.ctx.Done():
			timer.Stop()
			return
		case <-d.connection.packets.Done():
			timer.Stop()
			return
		case <-changed:
			timer.Stop()
		case <-timer.C:
		case <-ticker.C:
			timer.Stop()
			lease, valid := a.currentLease(d.proof)
			if c, present := a.Publishers.nativeCandidate(d.claim.ref, lease); !valid || !present || c != d.connection {
				return
			}
		}
	}
}

func (d *nativeDelivery) renew(ctx context.Context, a *NativeConnectorAcceptor, outer muxsession.Session, proof tunnelv1.NativePairLegProof) (tunnelv1.NativePairLegAccepted, error) {
	denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	d.mu.Lock()
	until := d.until
	d.mu.Unlock()
	if d.ctx.Err() != nil || !until.After(time.Now()) {
		return tunnelv1.NativePairLegAccepted{}, denied
	}
	call, stop := context.WithTimeout(ctx, min(2*time.Second, time.Until(until)))
	defer stop()
	next, err := a.claim(call, outer, proof)
	if err != nil {
		if d.ctx.Err() == nil && isRetryableControlError(err) {
			return tunnelv1.NativePairLegAccepted{}, errors.Join(err, &tunnel.ProtocolError{Code: tunnelv1.Unavailable})
		}
		return tunnelv1.NativePairLegAccepted{}, err
	}
	if next.ref != d.claim.ref || next.key != d.claim.key || next.receipt.DeliveryID != d.claim.receipt.DeliveryID || next.receipt.SourceIP != d.claim.receipt.SourceIP {
		return tunnelv1.NativePairLegAccepted{}, denied
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ctx.Err() != nil || !d.until.After(time.Now()) || !next.receipt.ExpiresAt.After(time.Now()) || call.Err() != nil {
		return tunnelv1.NativePairLegAccepted{}, denied
	}
	if d.bridge != nil {
		d.bridge.mu.Lock()
		defer d.bridge.mu.Unlock()
		if d.bridge.active != d || d.bridge.ctx.Err() != nil || !d.bridge.until.After(time.Now()) {
			return tunnelv1.NativePairLegAccepted{}, denied
		}
		d.bridge.until = next.receipt.ExpiresAt
	}
	d.until = next.receipt.ExpiresAt
	close(d.changed)
	d.changed = make(chan struct{})
	return next.receipt, nil
}

// nativeBridge owns the registration and replay history independently of any
// raced candidate. a signed exact-predecessor handoff changes only delivery.
type nativeBridge struct {
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	publisher peer.Carrier
	connector *peer.CarrierSlot
	mu        sync.Mutex
	active    *nativeDelivery
	nonce     []byte
	used      map[[32]byte]bool
	until     time.Time
	claim     nativeConnectorClaim
	proof     tunnelv1.NativePairLegProof
}

func (p *nativePacketSession) selectBridge(ctx context.Context, a *NativeConnectorAcceptor, d *nativeDelivery, id [16]byte, selection tunnelv1.NativeLegBinding) (*nativeBridge, error) {
	denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	if !selection.Matches(d.proof) {
		return nil, denied
	}
	lease, valid := a.currentLease(d.proof)
	if c, present := a.Publishers.nativeCandidate(d.claim.ref, lease); !valid || !present || c != d.connection {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ctx.Err() != nil || ctx.Err() != nil {
		return nil, errors.Join(denied, net.ErrClosed)
	}
	b := p.bridges[id]
	nonce := [32]byte(selection.Nonce)
	if len(selection.PreviousNonce) != 0 {
		if b == nil {
			return nil, denied
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.ctx.Err() != nil || !b.until.After(time.Now()) || b.used[nonce] || len(b.used) >= 64 || !bytes.Equal(b.nonce, selection.PreviousNonce) || !b.proof.SameLeg(d.proof) || b.claim.key != d.claim.key || b.claim.ref != d.claim.ref || b.claim.receipt.SourceIP != d.claim.receipt.SourceIP {
			return nil, denied
		}
		old := b.active
		b.until = minDeadline(b.until, d.until)
		d.until = b.until
		b.active, b.nonce, b.used[nonce] = d, bytes.Clone(selection.Nonce), true
		if err := b.connector.Install(&nativeReadyCarrier{Carrier: d.carrier, cancel: d.cancel}); err != nil {
			b.cancel()
			return nil, err
		}
		if old != nil {
			old.cancel()
		}
		return b, nil
	}
	if b != nil {
		return nil, denied
	}
	if len(p.bridges) >= maxNativeConnectorSessions {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
	}
	carrier, err := p.Register(peerBinding(d.claim, id, 0), true)
	if err != nil {
		return nil, errors.Join(err, &tunnel.ProtocolError{Code: tunnelv1.Unavailable})
	}
	life, cancel := context.WithCancel(p.ctx)
	b = &nativeBridge{ctx: life, cancel: cancel, done: make(chan struct{}), publisher: carrier, connector: peer.NewCarrierSlot(), active: d, nonce: bytes.Clone(selection.Nonce), used: map[[32]byte]bool{nonce: true}, until: d.until, claim: d.claim, proof: d.proof}
	_ = b.connector.Install(&nativeReadyCarrier{Carrier: d.carrier, cancel: d.cancel})
	p.bridges[id] = b
	go b.serve(p, a, d.connection, id)
	return b, nil
}

func minDeadline(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (b *nativeBridge) detach(d *nativeDelivery) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active == d {
		b.active = nil
		_ = b.connector.Install(nil)
	}
}

func (b *nativeBridge) serve(owner *nativePacketSession, a *NativeConnectorAcceptor, connection *serviceConnection, id [16]byte) {
	defer close(b.done)
	var workers sync.WaitGroup
	finished := make(chan error, 2)
	workers.Go(func() { finished <- forwardNativePackets(b.ctx, peer.RetainCarrierReplay(b.connector), b.publisher) })
	workers.Go(func() { finished <- forwardNativePackets(b.ctx, b.publisher, b.connector) })
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
		owner.mu.Lock()
		delete(owner.bridges, id)
		owner.mu.Unlock()
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		b.mu.Lock()
		until := b.until
		if !until.After(time.Now()) {
			b.cancel()
		}
		b.mu.Unlock()
		timer := time.NewTimer(time.Until(until))
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
			lease, valid := a.currentLease(b.proof)
			if c, present := a.Publishers.nativeCandidate(b.claim.ref, lease); !valid || !present || c != connection {
				return
			}
		}
	}
}

func forwardNativePackets(ctx context.Context, source, destination peer.Carrier) error {
	for {
		frame, err := source.Receive(ctx)
		if err != nil {
			return err
		}
		call, stop := context.WithTimeout(ctx, time.Second)
		err = destination.Send(call, frame)
		stop()
		if err != nil {
			return err
		}
	}
}

// a replacement TLS stream introduces itself with its first authenticated
// packet. publisher probes before that point are dropped, not queued or replayed.
type nativeReadyCarrier struct {
	peer.Carrier
	ready  atomic.Bool
	cancel context.CancelFunc
}

func (c *nativeReadyCarrier) Send(ctx context.Context, frame []byte) error {
	if !c.ready.Load() {
		return context.Cause(ctx)
	}
	err := c.Carrier.Send(ctx, frame)
	if err != nil {
		c.cancel()
	}
	return err
}

func (c *nativeReadyCarrier) Receive(ctx context.Context) ([]byte, error) {
	frame, err := c.Carrier.Receive(ctx)
	if err == nil {
		c.ready.Store(true)
	} else {
		c.cancel()
	}
	return frame, err
}

func (c *nativeReadyCarrier) Close() error { c.cancel(); return c.Carrier.Close() }
