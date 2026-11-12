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
	install sync.Mutex
	mu      sync.Mutex
	closed  bool
	bridges map[[16]byte]*connectorBridge
	once    sync.Once
}

func newConnectorPacketSession(parent context.Context, outer muxsession.Session) (*connectorPacketSession, error) {
	packets, err := peer.NewSharedSession(parent, outer)
	if err != nil {
		return nil, err
	}
	return &connectorPacketSession{SharedSession: packets, bridges: make(map[[16]byte]*connectorBridge)}, nil
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
		_ = p.SharedSession.Close()
		for _, bridge := range bridges {
			<-bridge.done
		}
	})
}

func (p *connectorPacketSession) stoppedLocked() bool {
	if p.closed {
		return true
	}
	select {
	case <-p.Done():
		return true
	default:
		return false
	}
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
	ctx             context.Context
	cancel          context.CancelFunc
	claim           connectorClaim
	proof           tunnelv1.ConnectorPairLegProof
	carrier         *connectorBindingCarrier
	bridge          atomic.Pointer[connectorBridge]
	stopPreparation func()
}

// a candidate spends one immutable opening deadline. activation joins its
// preparation worker before transferring authority to the bridge; no carrier
// timer remains that could later cancel an independently renewed binding.
func newConnectorDelivery(ctx context.Context, publisher <-chan struct{}, proof tunnelv1.ConnectorPairLegProof, claim connectorClaim) *connectorDelivery {
	life, cancel := context.WithCancel(ctx)
	d := &connectorDelivery{ctx: life, cancel: cancel, proof: proof, claim: claim}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		timer := time.NewTimer(time.Until(claim.receipt.ExpiresAt))
		defer timer.Stop()
		select {
		case <-stop:
			return
		case <-life.Done():
		case <-publisher:
		case <-timer.C:
		}
		cancel()
	}()
	d.stopPreparation = sync.OnceFunc(func() {
		close(stop)
		<-done
	})
	return d
}

func (d *connectorDelivery) close() {
	d.cancel()
	d.stopPreparation()
	if b := d.bridge.Load(); b != nil {
		b.detach(d)
	}
}

func connectorProbe(packet tunnelv1.PeerPacket) bool {
	return packet.Kind == tunnelv1.PeerProbe || packet.Kind == tunnelv1.PeerProbeReply
}

func (d *connectorDelivery) admit(packet tunnelv1.PeerPacket) bool {
	if b := d.bridge.Load(); b != nil {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.admitLocked(d, packet)
	}
	return d.ctx.Err() == nil && d.claim.receipt.ExpiresAt.After(time.Now()) && d.claim.source.check() == nil && connectorProbe(packet)
}

func (d *connectorDelivery) renew(ctx context.Context, a *ConnectorAcceptor, outer muxsession.Session, proof tunnelv1.ConnectorPairLegProof) (tunnelv1.ConnectorPairLegAccepted, error) {
	denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	b := d.bridge.Load()
	until := d.claim.receipt.ExpiresAt
	if b != nil {
		b.mu.Lock()
		until = b.until
		b.mu.Unlock()
	}
	if !until.After(time.Now()) {
		return tunnelv1.ConnectorPairLegAccepted{}, connectorClaimError(errors.Join(denied, context.Cause(d.ctx), context.Cause(ctx)))
	}
	// publisher packet teardown can cancel delivery while a renewal is already
	// being read. that local loss supplies no authorization decision, and must
	// not terminate the connector's retained inner connection as a subject denial.
	if cause := errors.Join(context.Cause(d.ctx), context.Cause(ctx)); cause != nil {
		return tunnelv1.ConnectorPairLegAccepted{}, connectorClaimError(cause)
	}
	if err := d.claim.source.check(); err != nil {
		return tunnelv1.ConnectorPairLegAccepted{}, connectorClaimError(errors.Join(err, context.Cause(d.ctx), context.Cause(ctx)))
	}
	call, stop := context.WithTimeout(ctx, min(2*time.Second, time.Until(until)))
	defer stop()
	next, err := a.claimFromControl(call, outer, proof)
	var bridgeCause error
	state := d.claim.receipt.BindingState
	if b != nil {
		b.mu.Lock()
		defer b.mu.Unlock()
		until, state, bridgeCause = b.until, b.state, context.Cause(b.ctx)
	}
	// authorization facts precede physical loss. only this bridge lock guards
	// the active deadline, admission state, and carrier through installation.
	invalid := !until.After(time.Now())
	if err == nil {
		invalid = invalid || !d.proof.SameLeg(proof) || next.ref != d.claim.ref || next.key != d.claim.key || next.receipt.DeliveryID != d.claim.receipt.DeliveryID || next.receipt.SourceIP != d.claim.receipt.SourceIP ||
			!next.receipt.ExpiresAt.After(time.Now()) || state == tunnelv1.ConnectorPeerLegBindingActive && next.receipt.BindingState != tunnelv1.ConnectorPeerLegBindingActive
	}
	if invalid {
		err = errors.Join(err, denied)
	}
	if b != nil && b.active != d {
		// the selected socket is local delivery state, not a subject denial.
		err = errors.Join(err, &tunnel.ProtocolError{Code: tunnelv1.Unavailable})
	}
	if err = errors.Join(err, d.claim.source.check(), context.Cause(d.ctx), context.Cause(call), bridgeCause); err != nil {
		return tunnelv1.ConnectorPairLegAccepted{}, connectorClaimError(err)
	}
	if b == nil && next.receipt.ExpiresAt.Before(until) {
		// an immutable candidate cannot adopt a shorter preparation grant.
		// retire it rather than later activating under the older opening budget.
		d.cancel()
		return tunnelv1.ConnectorPairLegAccepted{}, errors.Join(&tunnel.ProtocolError{Code: tunnelv1.Unavailable}, context.Cause(d.ctx))
	}
	// repeating a pending claim spends its original preparation deadline. only
	// a revalidated, explicit active claim can open data and renew its authority.
	if (b == nil || next.receipt.BindingState != tunnelv1.ConnectorPeerLegBindingActive) && next.receipt.ExpiresAt.After(until) {
		next.receipt.ExpiresAt = until
	}
	if b != nil {
		b.until, b.state = next.receipt.ExpiresAt, next.receipt.BindingState
	}
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
	state     tunnelv1.ConnectorPeerLegBindingState
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
	connection, present := a.Publishers.connectorCandidate(d.claim.ref, lease)
	if !valid || !present || connection.packets != p {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
	}
	if _, replacement := activation.Replacement(); replacement {
		p.mu.Lock()
		b := p.bridges[id]
		closed := p.stoppedLocked() || ctx.Err() != nil
		p.mu.Unlock()
		if closed || b == nil {
			return nil, errors.Join(&tunnel.ProtocolError{Code: tunnelv1.Unavailable}, context.Cause(ctx))
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
	connection, present = a.Publishers.connectorCandidate(d.claim.ref, lease)
	if !valid || !present || connection.packets != p {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
	}
	p.mu.Lock()
	if !d.claim.receipt.ExpiresAt.After(time.Now()) {
		p.mu.Unlock()
		return nil, denied
	}
	if p.stoppedLocked() || ctx.Err() != nil || d.ctx.Err() != nil {
		p.mu.Unlock()
		return nil, errors.Join(&tunnel.ProtocolError{Code: tunnelv1.Unavailable}, net.ErrClosed, context.Cause(ctx), context.Cause(d.ctx))
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
	// the packet owner, not the selected connector socket, owns this retained
	// bridge. serve observes the actual borrowed transport lifetime and Close
	// joins every registered bridge before the packet owner returns.
	life, cancel := context.WithCancel(context.Background())
	b = &connectorBridge{ctx: life, cancel: cancel, done: make(chan struct{}),
		connector: connector, active: d, until: d.claim.receipt.ExpiresAt, state: d.claim.receipt.BindingState, claim: d.claim, proof: d.proof,
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
	go b.serve(p, a, connection, id)
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
	return b.active != nil && b.admitLocked(b.active, packet)
}

func (b *connectorBridge) admitLocked(d *connectorDelivery, packet tunnelv1.PeerPacket) bool {
	return b.ctx.Err() == nil && b.until.After(time.Now()) && b.active == d && d.ctx.Err() == nil && d.claim.source.check() == nil &&
		(b.state == tunnelv1.ConnectorPeerLegBindingActive || connectorProbe(packet))
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
	if !b.until.After(time.Now()) || !d.claim.receipt.ExpiresAt.After(time.Now()) ||
		!b.proof.SameLeg(d.proof) ||
		b.claim.key != d.claim.key || b.claim.ref != d.claim.ref || b.claim.receipt.SourceIP != d.claim.receipt.SourceIP {
		b.mu.Unlock()
		return nil, denied
	}
	handoff := b.handoff
	switch handoff.record(selection, d.proof.RequestedAt) {
	case handoffRejected:
		b.mu.Unlock()
		return nil, denied
	case handoffExhausted:
		b.mu.Unlock()
		return nil, &tunnel.ProtocolError{Code: tunnelv1.HandoffRevisionExhausted}
	}
	if cause := errors.Join(context.Cause(ctx), context.Cause(d.ctx), context.Cause(b.ctx)); cause != nil {
		b.mu.Unlock()
		return nil, connectorClaimError(cause)
	}
	b.handoff = handoff
	old := b.active
	// reconnection spends the previous deadline; only ordinary renewal can
	// advance authority. the fresh socket claim may narrow it.
	if d.claim.receipt.ExpiresAt.Before(b.until) {
		b.until = d.claim.receipt.ExpiresAt
	}
	// each freshly selected carrier must independently confirm active admission.
	// a prepared claim cannot inherit the predecessor's data gate.
	b.state = d.claim.receipt.BindingState
	b.active = d
	b.mu.Unlock()
	return b.installCarrier(ctx, d, old)
}

// installCarrier is called with the transition lock, never the authority lock.
// its logical operation was already recorded and survives candidate loss.
func (b *connectorBridge) installCarrier(ctx context.Context, d, old *connectorDelivery) (*connectorBridge, error) {
	d.stopPreparation()
	d.bridge.Store(b)
	err := b.connector.Install(d.carrier)
	if old != nil {
		old.cancel()
	}
	b.mu.Lock()
	expired := !b.until.After(time.Now())
	current := err == nil && b.ctx.Err() == nil && !expired
	lost := ctx.Err() != nil || d.ctx.Err() != nil
	if lost && b.active == d {
		b.active = nil
	}
	b.mu.Unlock()
	if expired {
		b.cancel()
		return nil, errors.Join(&tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}, err, context.DeadlineExceeded, context.Cause(ctx), context.Cause(d.ctx))
	}
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
		case <-owner.Done():
			timer.Stop()
			return
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
