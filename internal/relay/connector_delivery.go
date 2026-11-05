package relay

import (
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

// connectorPacketSession owns delivery registrations for this publisher connection.
// it owns no application admission or visitor permission.
type connectorPacketSession struct {
	*peer.SharedSession
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	closed  bool
	bridges map[[16]byte]*connectorBridge
	once    sync.Once
}

func newConnectorPacketSession(parent context.Context, outer muxsession.Session) (*connectorPacketSession, error) {
	ctx, cancel := context.WithCancel(parent)
	packets, err := peer.NewSharedSession(ctx, outer)
	if err != nil {
		cancel()
		return nil, err
	}
	return &connectorPacketSession{SharedSession: packets, ctx: ctx, cancel: cancel, bridges: make(map[[16]byte]*connectorBridge)}, nil
}

func (p *connectorPacketSession) Close() {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		bridges := make([]*connectorBridge, 0, len(p.bridges))
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

func (r *ServiceRegistry) connectorCandidate(ref tunnelv1.ServicePublisherConnectionRef, lease relayv1.RelayLease) (*serviceConnection, bool) {
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

func peerBinding(claim connectorClaim, id [16]byte, role uint8) peer.PairBinding {
	return peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: id, Generation: uint64(claim.receipt.DeliveryGeneration)}, Key: claim.key, Path: uint8(claim.receipt.ConnectionSlot), Role: role}
}

type connectorDelivery struct {
	ctx        context.Context
	cancel     context.CancelFunc
	claim      connectorClaim
	proof      tunnelv1.ConnectorPairLegProof
	connection *serviceConnection
	carrier    peer.Carrier
	mu         sync.Mutex
	until      time.Time
	changed    chan struct{}
	bridge     *connectorBridge
}

func (d *connectorDelivery) watch(a *ConnectorAcceptor) {
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
			if c, present := a.Publishers.connectorCandidate(d.claim.ref, lease); !valid || !present || c != d.connection {
				return
			}
		}
	}
}

func (d *connectorDelivery) renew(ctx context.Context, a *ConnectorAcceptor, outer muxsession.Session, proof tunnelv1.ConnectorPairLegProof) (tunnelv1.ConnectorPairLegAccepted, error) {
	denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	d.mu.Lock()
	until := d.until
	d.mu.Unlock()
	if d.ctx.Err() != nil || !until.After(time.Now()) {
		return tunnelv1.ConnectorPairLegAccepted{}, denied
	}
	call, stop := context.WithTimeout(ctx, min(2*time.Second, time.Until(until)))
	defer stop()
	next, err := a.claim(call, outer, proof)
	if err != nil {
		return tunnelv1.ConnectorPairLegAccepted{}, err
	}
	if next.ref != d.claim.ref || next.key != d.claim.key || next.receipt.DeliveryID != d.claim.receipt.DeliveryID || next.receipt.SourceIP != d.claim.receipt.SourceIP {
		return tunnelv1.ConnectorPairLegAccepted{}, denied
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ctx.Err() != nil || !d.until.After(time.Now()) || !next.receipt.ExpiresAt.After(time.Now()) || call.Err() != nil {
		return tunnelv1.ConnectorPairLegAccepted{}, denied
	}
	if d.bridge != nil {
		d.bridge.mu.Lock()
		defer d.bridge.mu.Unlock()
		if d.bridge.active != d || d.bridge.ctx.Err() != nil || !d.bridge.until.After(time.Now()) {
			return tunnelv1.ConnectorPairLegAccepted{}, denied
		}
		d.bridge.until = next.receipt.ExpiresAt
	}
	d.until = next.receipt.ExpiresAt
	close(d.changed)
	d.changed = make(chan struct{})
	return next.receipt, nil
}

// connectorBridge retains the publisher registration and replay state while a
// connector carrier is absent. only an exact authenticated predecessor handoff
// may replace that carrier, before the last confirmed deadline.
type connectorBridge struct {
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	publisher *peer.ForwardingRegistration
	connector *peer.CarrierSlot
	replace   sync.Mutex
	mu        sync.Mutex
	active    *connectorDelivery
	handoff   handoffState
	until     time.Time
	claim     connectorClaim
	proof     tunnelv1.ConnectorPairLegProof
}

func (p *connectorPacketSession) selectBridge(ctx context.Context, a *ConnectorAcceptor, d *connectorDelivery, id [16]byte, selection tunnelv1.ConnectorLegBinding) (*connectorBridge, error) {
	denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	activation, err := selection.Activation()
	if err != nil || !activation.Matches(d.proof) {
		return nil, denied
	}
	lease, valid := a.currentLease(d.proof)
	if c, present := a.Publishers.connectorCandidate(d.claim.ref, lease); !valid || !present || c != d.connection {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
	}
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil || ctx.Err() != nil {
		p.mu.Unlock()
		return nil, errors.Join(denied, net.ErrClosed)
	}
	b := p.bridges[id]
	if _, replacement := activation.Replacement(); replacement {
		p.mu.Unlock()
		if b == nil {
			return nil, denied
		}
		return b.replaceCarrier(ctx, d, activation)
	}
	defer p.mu.Unlock()
	if b != nil {
		return nil, denied
	}
	if len(p.bridges) >= maxConnectorSessions {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
	}
	connector := peer.NewCarrierSlot()
	carrier, err := p.RegisterForwarding(peerBinding(d.claim, id, 0), true, connector)
	if err != nil {
		_ = connector.Close()
		return nil, errors.Join(err, &tunnel.ProtocolError{Code: tunnelv1.Unavailable})
	}
	life, cancel := context.WithCancel(p.ctx)
	b = &connectorBridge{ctx: life, cancel: cancel, done: make(chan struct{}), publisher: carrier,
		connector: connector, active: d, until: d.until, claim: d.claim, proof: d.proof,
		handoff: initialHandoff(activation, d.proof.RequestedAt)}
	_ = b.connector.Install(&connectorReadyCarrier{Carrier: d.carrier, cancel: d.cancel})
	p.bridges[id] = b
	go b.serve(p, a, d.connection, id)
	return b, nil
}

func (b *connectorBridge) replaceCarrier(ctx context.Context, d *connectorDelivery, selection tunnelv1.ConnectorActivation) (*connectorBridge, error) {
	denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	if !selection.Matches(d.proof) {
		return nil, denied
	}
	b.replace.Lock()
	defer b.replace.Unlock()
	b.mu.Lock()
	if ctx.Err() != nil || d.ctx.Err() != nil || b.ctx.Err() != nil || !b.until.After(time.Now()) || !d.until.After(time.Now()) ||
		!b.proof.SameLeg(d.proof) ||
		b.claim.key != d.claim.key || b.claim.ref != d.claim.ref || b.claim.receipt.SourceIP != d.claim.receipt.SourceIP {
		b.mu.Unlock()
		return nil, denied
	}
	if b.handoff.record(selection, d.proof.RequestedAt) == handoffRejected {
		b.mu.Unlock()
		return nil, denied
	}
	old := b.active
	// reconnection spends the previous deadline; only ordinary renewal can
	// advance authority. the fresh socket claim may narrow it.
	if d.until.Before(b.until) {
		b.until = d.until
	}
	d.until = b.until
	b.active = d
	b.mu.Unlock()
	err := b.connector.Install(&connectorReadyCarrier{Carrier: d.carrier, cancel: d.cancel})
	if old != nil {
		old.cancel()
	}
	b.mu.Lock()
	current := err == nil && b.ctx.Err() == nil && b.until.After(time.Now())
	lost := ctx.Err() != nil || d.ctx.Err() != nil
	if lost && b.active == d {
		b.active = nil
	}
	b.mu.Unlock()
	if !current {
		b.cancel()
		return nil, errors.Join(denied, err, context.Cause(ctx))
	}
	if lost {
		// a committed handoff whose candidate disappeared keeps its chain and
		// publisher registration. a fresh socket can resume the same operation.
		_ = b.connector.Install(nil)
		return nil, errors.Join(&tunnel.ProtocolError{Code: tunnelv1.Unavailable}, context.Cause(ctx), context.Cause(d.ctx))
	}
	return b, nil
}

func (b *connectorBridge) detach(d *connectorDelivery) {
	b.replace.Lock()
	defer b.replace.Unlock()
	b.mu.Lock()
	active := b.active == d
	if b.active == d {
		b.active = nil
	}
	b.mu.Unlock()
	if active {
		_ = b.connector.Install(nil)
	}
}

func (b *connectorBridge) serve(owner *connectorPacketSession, a *ConnectorAcceptor, connection *serviceConnection, id [16]byte) {
	defer close(b.done)
	var workers sync.WaitGroup
	finished := make(chan error, 2)
	workers.Go(func() { finished <- b.publisher.ForwardToPublisher(b.ctx) })
	workers.Go(func() { finished <- b.publisher.ForwardToConnector(b.ctx) })
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
			if c, present := a.Publishers.connectorCandidate(b.claim.ref, lease); !valid || !present || c != connection {
				return
			}
		}
	}
}

// a TLS stream introduces itself with its first authenticated
// packet. publisher probes before that point are dropped, not queued or replayed.
type connectorReadyCarrier struct {
	peer.Carrier
	ready  atomic.Bool
	cancel context.CancelFunc
}

func (c *connectorReadyCarrier) Send(ctx context.Context, frame []byte) error {
	if !c.ready.Load() {
		return context.Cause(ctx)
	}
	err := c.Carrier.Send(ctx, frame)
	if err != nil {
		c.cancel()
	}
	return err
}

func (c *connectorReadyCarrier) Receive(ctx context.Context) ([]byte, error) {
	frame, err := c.Carrier.Receive(ctx)
	if err == nil {
		c.ready.Store(true)
	} else {
		c.cancel()
	}
	return frame, err
}

func (c *connectorReadyCarrier) Close() error { c.cancel(); return c.Carrier.Close() }
