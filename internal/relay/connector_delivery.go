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
	install sync.Mutex
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

func peerBinding(claim connectorClaim, id [16]byte, role uint8, admit func(tunnelv1.PeerPacket) bool) peer.PairBinding {
	return peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: id, Generation: uint64(claim.receipt.DeliveryGeneration)}, Key: claim.key, Path: uint8(claim.receipt.ConnectionSlot), Role: role, AdmitPacket: admit}
}

type connectorDelivery struct {
	ctx        context.Context
	cancel     context.CancelFunc
	claim      connectorClaim
	proof      tunnelv1.ConnectorPairLegProof
	connection *serviceConnection
	carrier    peer.Carrier
	binding    *connectorBindingCarrier
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
	if err := d.claim.source.check(); err != nil {
		return tunnelv1.ConnectorPairLegAccepted{}, err
	}
	call, stop := context.WithTimeout(ctx, min(2*time.Second, time.Until(until)))
	defer stop()
	next, err := a.claim(call, outer, proof)
	if err != nil {
		return tunnelv1.ConnectorPairLegAccepted{}, err
	}
	if !d.proof.SameLeg(proof) || next.ref != d.claim.ref || next.key != d.claim.key || next.receipt.DeliveryID != d.claim.receipt.DeliveryID || next.receipt.SourceIP != d.claim.receipt.SourceIP {
		return tunnelv1.ConnectorPairLegAccepted{}, denied
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ctx.Err() != nil || !d.until.After(time.Now()) || !next.receipt.ExpiresAt.After(time.Now()) || call.Err() != nil {
		return tunnelv1.ConnectorPairLegAccepted{}, denied
	}
	if err := d.claim.source.check(); err != nil {
		return tunnelv1.ConnectorPairLegAccepted{}, err
	}
	if d.claim.receipt.BindingState == tunnelv1.ConnectorPeerLegBindingActive && next.receipt.BindingState != tunnelv1.ConnectorPeerLegBindingActive {
		return tunnelv1.ConnectorPairLegAccepted{}, denied
	}
	// repeating a pending claim spends its original preparation deadline. only
	// a revalidated, explicit active claim can open data and renew its authority.
	if next.receipt.BindingState != tunnelv1.ConnectorPeerLegBindingActive && next.receipt.ExpiresAt.After(d.until) {
		next.receipt.ExpiresAt = d.until
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
	d.claim.receipt.BindingState = next.receipt.BindingState
	if d.binding != nil {
		d.binding.active.Store(next.receipt.BindingState == tunnelv1.ConnectorPeerLegBindingActive)
	}
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
	_, initialExplicit := activation.InitialOperation()
	if d.proof.DeliveryGeneration > 1 && !initialExplicit {
		if _, replacement := activation.Replacement(); !replacement {
			return nil, denied
		}
	}
	if err := d.claim.source.check(); err != nil {
		return nil, err
	}
	lease, valid := a.currentLease(d.proof)
	if c, present := a.Publishers.connectorCandidate(d.claim.ref, lease); !valid || !present || c != d.connection {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
	}
	if _, replacement := activation.Replacement(); replacement {
		p.mu.Lock()
		b := p.bridges[id]
		closed := p.closed || p.ctx.Err() != nil || ctx.Err() != nil
		p.mu.Unlock()
		if closed || b == nil {
			return nil, denied
		}
		return b.replaceCarrier(ctx, d, activation)
	}
	// new binding registrations serialize separately from state access. retiring
	// an older generation joins its physical work without holding the owner lock.
	// unchanged-binding handoffs keep their independent bridge transition lock.
	p.install.Lock()
	defer p.install.Unlock()
	p.mu.Lock()
	b := p.bridges[id]
	if b != nil && initialExplicit && d.proof.DeliveryGeneration == b.proof.DeliveryGeneration {
		p.mu.Unlock()
		return b.replaceCarrier(ctx, d, activation)
	}
	if b != nil && !b.canRebind(d) {
		p.mu.Unlock()
		return nil, denied
	}
	p.mu.Unlock()
	if b != nil {
		b.cancel()
		<-b.done
	}
	// authority may expire while the old registration joins. a new generation
	// must start a fresh initial activation, never inherit its handoff history.
	lease, valid = a.currentLease(d.proof)
	if c, present := a.Publishers.connectorCandidate(d.claim.ref, lease); !valid || !present || c != d.connection {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
	}
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil || ctx.Err() != nil || d.ctx.Err() != nil {
		p.mu.Unlock()
		return nil, errors.Join(&tunnel.ProtocolError{Code: tunnelv1.Unavailable}, net.ErrClosed, context.Cause(ctx), context.Cause(d.ctx))
	}
	if !d.until.After(time.Now()) {
		p.mu.Unlock()
		return nil, denied
	}
	if err := d.claim.source.check(); err != nil {
		p.mu.Unlock()
		return nil, err
	}
	if len(p.bridges) >= maxConnectorSessions {
		p.mu.Unlock()
		return nil, &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
	}
	connector := peer.NewCarrierSlot()
	life, cancel := context.WithCancel(p.ctx)
	b = &connectorBridge{ctx: life, cancel: cancel, done: make(chan struct{}),
		connector: connector, active: d, until: d.until, claim: d.claim, proof: d.proof,
		handoff: initialHandoff(activation, d.proof.RequestedAt)}
	carrier, err := p.RegisterForwarding(peerBinding(d.claim, id, 0, b.admit), true, connector)
	if err != nil {
		p.mu.Unlock()
		cancel()
		_ = connector.Close()
		return nil, errors.Join(err, &tunnel.ProtocolError{Code: tunnelv1.Unavailable})
	}
	b.publisher = carrier
	b.replace.Lock()
	defer b.replace.Unlock()
	// commit the stable initial operation before installing its candidate. a
	// canceled socket or lost acknowledgement must not strand this generation.
	p.bridges[id] = b
	go b.serve(p, a, d.connection, id)
	p.mu.Unlock()
	return b.installCarrier(ctx, d, nil)
}

func (b *connectorBridge) canRebind(d *connectorDelivery) bool {
	previousLeg := d.proof
	previousLeg.DeliveryGeneration = b.proof.DeliveryGeneration
	return d.proof.DeliveryGeneration > b.proof.DeliveryGeneration && b.proof.SameLeg(previousLeg) &&
		b.claim.ref == d.claim.ref && b.claim.receipt.DeliveryID == d.claim.receipt.DeliveryID &&
		d.claim.key != [32]byte{} && b.claim.key != d.claim.key
}

// the publisher registration outlives individual connector sockets. read the
// current candidate's gate at admission, before shared queues can retain data.
func (b *connectorBridge) admit(packet tunnelv1.PeerPacket) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ctx.Err() == nil && b.until.After(time.Now()) && b.active != nil && b.active.binding.admit(packet)
}

func (p *connectorPacketSession) removeBridge(id [16]byte, b *connectorBridge) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.bridges[id] == b {
		delete(p.bridges, id)
	}
}

func (b *connectorBridge) replaceCarrier(ctx context.Context, d *connectorDelivery, selection tunnelv1.ConnectorActivation) (*connectorBridge, error) {
	denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	if !selection.Matches(d.proof) {
		return nil, denied
	}
	if err := d.claim.source.check(); err != nil {
		return nil, err
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
	switch b.handoff.record(selection, d.proof.RequestedAt) {
	case handoffRejected:
		b.mu.Unlock()
		return nil, denied
	case handoffExhausted:
		b.mu.Unlock()
		return nil, &tunnel.ProtocolError{Code: tunnelv1.HandoffRevisionExhausted}
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
	return b.installCarrier(ctx, d, old)
}

// installCarrier is called with the transition lock, never the authority lock.
// its logical operation was already recorded and survives candidate loss.
func (b *connectorBridge) installCarrier(ctx context.Context, d, old *connectorDelivery) (*connectorBridge, error) {
	err := b.connector.Install(d.readyCarrier())
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
		return nil, errors.Join(&tunnel.ProtocolError{Code: tunnelv1.Unavailable}, err, context.Cause(ctx))
	}
	if sourceErr := d.claim.source.check(); sourceErr != nil {
		b.mu.Lock()
		if b.active == d {
			b.active = nil
		}
		b.mu.Unlock()
		_ = b.connector.Install(nil)
		return nil, sourceErr
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
		owner.removeBridge(id, b)
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
	source *connectorSocketSource
}

func (d *connectorDelivery) readyCarrier() *connectorReadyCarrier {
	return &connectorReadyCarrier{Carrier: d.carrier, cancel: d.cancel, source: d.claim.source}
}

func (c *connectorReadyCarrier) Send(ctx context.Context, frame []byte) error {
	if err := c.source.check(); err != nil {
		return err
	}
	if !c.ready.Load() {
		return context.Cause(ctx)
	}
	err := c.Carrier.Send(ctx, frame)
	if err != nil && !errors.Is(err, errConnectorSocketSourceChanged) {
		c.cancel()
	}
	return err
}

func (c *connectorReadyCarrier) Receive(ctx context.Context) ([]byte, error) {
	frame, err := c.Carrier.Receive(ctx)
	if err == nil {
		c.ready.Store(true)
	} else if !errors.Is(err, errConnectorSocketSourceChanged) {
		c.cancel()
	}
	return frame, err
}

func (c *connectorReadyCarrier) Close() error {
	// the packet slot retires immediately on source change. leave only its
	// bounded control stream alive so the next request receives the exact stale
	// result; canceling it here would erase that result into an outer close.
	if !errors.Is(c.source.check(), errConnectorSocketSourceChanged) {
		c.cancel()
	}
	return c.Carrier.Close()
}
