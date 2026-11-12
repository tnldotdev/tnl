package service

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const maxConnectorPeerOwners = 64
const maxConnectorPeerHistory = 4096
const maxConnectorPeerStreams = tunnel.MaxConnectorApplicationStreams

// PeerSession retains one exact control-delivered pair and its inner session.
// neither a carrier change nor a sibling connector changes this owner. a new
// pair/run needs a new owner; it cannot transfer the old owner's admissions.
type PeerSession struct {
	bound          *Bound
	identity       peerIdentity
	network        peerNetworkBinding
	lease          peerLease
	owner          peerLease
	pending        *PeerBinding
	deliveryState  peerDeliveryState
	highwater      int64
	installMu      sync.Mutex
	packets        *peer.Endpoint
	connectivity   *peer.Connectivity
	permissionGate tunnel.ConnectorPermissionGate
	packetPaths    [2]*peer.CarrierSlot
	deliverySlots  [2]*Claimed
	ctx            context.Context
	cancel         context.CancelFunc
	seen           map[string]struct{}
	streams        map[*connectorAdmission]struct{}
	serveOnce      sync.Once
	workers        sync.WaitGroup
	done           chan struct{}
	changed        chan struct{}
	replayUntil    time.Time
	ready          chan struct{}
	installedUntil time.Time
}

func (b *Bound) BindPeer(ctx context.Context, binding PeerBinding) (*PeerSession, error) {
	if b == nil || b.boundState == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrPrivateStream
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.peerCurrentLocked(binding) || !b.peerRelaysCurrentLocked(binding) || binding.state != controlv1.ConnectorPeerPairBindingActive || binding.operation != "" {
		return nil, ErrPrivateStream
	}
	for id, old := range b.connectorPeers {
		if !old.replayUntil.IsZero() && !old.replayUntil.After(time.Now()) {
			select {
			case <-old.done:
				delete(b.connectorPeers, id)
			default:
			}
		}
	}
	if b.connectorPeers[binding.pairID] != nil || len(b.connectorPeers) >= maxConnectorPeerOwners {
		return nil, ErrPrivateStream
	}
	if b.connectorPeers == nil {
		b.connectorPeers = make(map[string]*PeerSession)
	}
	life, cancel := context.WithCancel(ctx)
	p := &PeerSession{bound: b, identity: binding.peerIdentity, network: binding.peerNetworkBinding, lease: binding.peerLease, owner: binding.peerLease, highwater: binding.generation, deliveryState: peerDeliveryActive, ctx: life, cancel: cancel, seen: make(map[string]struct{}), streams: make(map[*connectorAdmission]struct{}), done: make(chan struct{}), changed: make(chan struct{}), ready: make(chan struct{})}
	b.connectorPeers[binding.pairID] = p
	return p, nil
}

// Renew installs a newly authenticated delivery for this exact retained owner.
// it cannot revive an expired peer, change its source/subject/key, transfer a
// replacement pair or run, or reset any admitted stream's setup deadline.
func (p *PeerSession) Renew(binding PeerBinding) error {
	if p == nil || p.bound == nil || p.bound.boundState == nil {
		return ErrPrivateStream
	}
	b := p.bound
	b.mu.Lock()
	defer b.mu.Unlock()
	valid := p.deliveryCurrentLocked() && b.peerCurrentLocked(binding) && b.peerRelaysCurrentLocked(binding) &&
		binding.peerIdentity == p.identity && binding.peerNetworkBinding == p.network && binding.state == controlv1.ConnectorPeerPairBindingActive && p.pending == nil
	if !valid {
		return ErrPrivateStream
	}
	if !binding.observedAt.After(p.lease.observedAt) {
		return nil
	}
	next := binding.peerLease
	if !next.authorityUntil.After(p.lease.authorityUntil) {
		next.until = peerDeadline(next.until, p.lease.until)
	}
	p.lease = next
	p.observeOwnerLocked(next)
	close(p.changed)
	p.changed = make(chan struct{})
	return nil
}

func (p *PeerSession) currentLocked() bool {
	return p.replayUntil.IsZero() && p.ctx.Err() == nil && p.owner.until.After(time.Now()) &&
		p.bound.connectorPeers[p.identity.pairID] == p && p.bound.peerIdentityCurrentLocked(p.identity)
}

func (p *PeerSession) deliveryCurrentLocked() bool {
	return p.currentLocked() && p.deliveryState == peerDeliveryActive && p.pending == nil && p.lease.until.After(time.Now()) &&
		(p.installedUntil.IsZero() || p.installedUntil.After(time.Now())) && p.bound.peerRelaysCurrentLocked(p.bindingLocked())
}

func (p *PeerSession) watch() {
	defer p.stop()
	for {
		p.bound.mu.Lock()
		current := p.currentLocked()
		until, changed := p.owner.until, p.changed
		binding := p.deliveryBindingLocked()
		suspend := false
		if p.pending != nil && p.deliveryState != peerDeliveryRetired {
			until = peerDeadline(until, p.pending.until)
			suspend = !p.pending.until.After(time.Now())
		} else if p.deliveryState == peerDeliveryActive {
			until = peerDeadline(until, p.lease.until)
			if !p.installedUntil.IsZero() {
				until = peerDeadline(until, p.installedUntil)
			}
			suspend = !until.After(time.Now())
		}
		p.bound.mu.Unlock()
		if !current {
			return
		}
		if suspend {
			p.detachDelivery(binding.peerNetworkBinding)
			continue
		}
		timer := time.NewTimer(time.Until(until))
		select {
		case <-p.ctx.Done():
			timer.Stop()
			return
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (p *PeerSession) bindingSnapshot() PeerBinding {
	p.bound.mu.Lock()
	defer p.bound.mu.Unlock()
	return p.bindingLocked()
}

func (p *PeerSession) bindingLocked() PeerBinding {
	return PeerBinding{peerIdentity: p.identity, peerNetworkBinding: p.network, peerLease: p.lease}
}

func (p *PeerSession) stop() {
	b := p.bound
	b.mu.Lock()
	if p.replayUntil.IsZero() {
		p.replayUntil = time.Now().Add(5 * time.Minute)
	}
	b.mu.Unlock()
	p.cancel()
}

func (p *PeerSession) Close() {
	p.stop()
	// closing a reservation before Serve consumes its single serving attempt.
	p.serveOnce.Do(func() { close(p.done) })
	<-p.done
}

// Serve owns setup, the renewable deadline watch, the retained inner session,
// and joined teardown. application streams still prove their own signed visits.
func (p *PeerSession) Serve(ctx context.Context) error {
	return p.serve(ctx, func() error { return p.serveRelayPackets(ctx) })
}

// setup and serving share one deadline watch and completion barrier. a setup
// failure has the same joined retirement as a terminal inner session.
func (p *PeerSession) serve(ctx context.Context, run func() error) error {
	if p == nil || ctx == nil {
		return ErrPrivateStream
	}
	started := false
	p.serveOnce.Do(func() { started = true })
	if !started {
		return ErrPrivateStream
	}
	stop := context.AfterFunc(ctx, p.cancel)
	watchDone := make(chan struct{})
	go func() { defer close(watchDone); p.watch() }()
	defer func() {
		p.stop()
		stop()
		<-watchDone
		p.workers.Wait()
		close(p.done)
	}()
	p.bound.mu.Lock()
	current := ctx.Err() == nil && p.currentLocked()
	p.bound.mu.Unlock()
	if !current {
		return ErrPrivateStream
	}
	return run()
}

func (p *PeerSession) serveSession(session muxsession.Session) error {
	defer session.Close()
	defer p.stop()
	setup, cancelSetup := context.WithTimeout(p.ctx, 10*time.Second)
	permissions, err := tunnel.AcceptConnectorPermissionControl(setup, session)
	cancelSetup()
	if err != nil {
		if p.ctx.Err() != nil || errors.Is(err, muxsession.ErrClosed) {
			return nil
		}
		return err
	}
	control, cancelControl := context.WithCancel(p.ctx)
	controlDone := make(chan struct{})
	go func() {
		defer close(controlDone)
		_ = tunnel.ServeConnectorPermissionControl(control, permissions, p.dispatchPermission, p.stop, &p.permissionGate)
	}()
	defer func() { cancelControl(); <-controlDone }()
	for {
		stream, err := session.AcceptStream(p.ctx)
		if err != nil {
			if p.ctx.Err() != nil || errors.Is(err, muxsession.ErrClosed) {
				return nil
			}
			return err
		}
		a, err := p.reserve(p.ctx, stream)
		if err != nil {
			_ = stream.Close()
			continue
		}
		go func() { defer p.workers.Done(); _ = a.forwardPeer() }()
	}
}

// connectorAdmission is the only connector stream-use issuer. its private construction
// retains the exact peer, pending charge, stream and verified guard. all mutable
// admission/owner/C state uses Bound.mu; pure guard entry then takes Lease.mu.
// the lease never calls service code while locked, so this order has no reverse
// edge. network I/O, cancellation, physical close and joins happen unlocked.
type connectorAdmission struct {
	peer       *PeerSession
	ctx        context.Context
	caller     context.Context
	cancel     context.CancelFunc
	stream     net.Conn
	guard      *visitorlease.ConnectorGuard
	entry      tunnelv1.ConnectorPeerVisitorEntry
	permission visitortoken.VerifiedPermission
	renewals   chan connectorPermissionRenewal
	renewDone  chan struct{}
	lastUpdate uint64
	state      connectorAdmissionState // protected by Bound.mu
	setupUntil time.Time
	timer      *time.Timer
	timerDone  chan struct{}
	closeOnce  sync.Once
	closeErr   error
	audit      serviceaudit.Observation
}

// the phase owns both capacity charges and the setup deadline's timer. retiring
// keeps the previous phase until physical close and renewal workers have joined.
// only the owning worker releases charges, never Stop or a deadline callback.
type connectorAdmissionState interface{ connectorAdmissionState() }

type reservedConnectorAdmission struct{}
type chargedConnectorAdmission struct{}
type admittedConnectorAdmission struct{}
type readyConnectorAdmission struct{}
type retiringConnectorAdmission struct{ previous connectorAdmissionState }
type releasedConnectorAdmission struct{}

func (reservedConnectorAdmission) connectorAdmissionState() {}
func (chargedConnectorAdmission) connectorAdmissionState()  {}
func (admittedConnectorAdmission) connectorAdmissionState() {}
func (readyConnectorAdmission) connectorAdmissionState()    {}
func (retiringConnectorAdmission) connectorAdmissionState() {}
func (releasedConnectorAdmission) connectorAdmissionState() {}

func (a *connectorAdmission) activeLocked() connectorAdmissionState {
	if retiring, ok := a.state.(retiringConnectorAdmission); ok {
		return retiring.previous
	}
	return a.state
}

func (a *connectorAdmission) admittedLocked() bool {
	switch a.activeLocked().(type) {
	case admittedConnectorAdmission, readyConnectorAdmission:
		return true
	default:
		return false
	}
}

func (a *connectorAdmission) chargedLocked() bool {
	switch a.activeLocked().(type) {
	case chargedConnectorAdmission, admittedConnectorAdmission, readyConnectorAdmission:
		return true
	default:
		return false
	}
}

func (a *connectorAdmission) readyLocked() bool {
	_, ok := a.activeLocked().(readyConnectorAdmission)
	return ok
}

func (a *connectorAdmission) retiringLocked() bool {
	_, ok := a.state.(retiringConnectorAdmission)
	return ok
}

func (a *connectorAdmission) retireLocked() {
	if !a.retiringLocked() {
		if _, released := a.state.(releasedConnectorAdmission); released {
			return
		}
		a.state = retiringConnectorAdmission{previous: a.state}
	}
}

func (p *PeerSession) reserve(caller context.Context, stream net.Conn) (*connectorAdmission, error) {
	b := p.bound
	b.mu.Lock()
	defer b.mu.Unlock()
	limit := b.streamCapacity
	if limit == 0 {
		limit = 64
	}
	if caller.Err() != nil || !p.deliveryCurrentLocked() || b.connectorPending >= min(limit, 4096) || len(p.streams) >= maxConnectorPeerStreams {
		return nil, ErrPrivateStream
	}
	life, cancel := context.WithCancel(p.ctx)
	a := &connectorAdmission{peer: p, ctx: life, caller: caller, cancel: cancel, stream: stream, state: reservedConnectorAdmission{}, setupUntil: time.Now().Add(10 * time.Second), timerDone: make(chan struct{})}
	a.timer = time.AfterFunc(time.Until(a.setupUntil), func() { defer close(a.timerDone); a.stopAndClose() })
	p.streams[a] = struct{}{}
	b.connectorPending++
	p.workers.Add(1)
	return a, nil
}

func (a *connectorAdmission) Stop() {
	b := a.peer.bound
	b.mu.Lock()
	a.retireLocked()
	b.mu.Unlock()
	a.cancel()
}

func (a *connectorAdmission) closeStream() error {
	a.closeOnce.Do(func() { a.closeErr = a.stream.Close() })
	return a.closeErr
}

func (a *connectorAdmission) stopAndClose() { a.Stop(); _ = a.closeStream() }

func (a *connectorAdmission) CheckUse(ctx context.Context) (time.Time, error) {
	b := a.peer.bound
	b.mu.Lock()
	defer b.mu.Unlock()
	if a.retiringLocked() || !a.admittedLocked() || !a.readyLocked() && !time.Now().Before(a.setupUntil) || a.ctx.Err() != nil || a.caller.Err() != nil || ctx.Err() != nil || !a.peer.currentLocked() {
		return time.Time{}, ErrPrivateStream
	}
	until, err := a.guard.Current()
	if a.peer.owner.until.Before(until) {
		until = a.peer.owner.until
	}
	if !a.readyLocked() && a.setupUntil.Before(until) {
		until = a.setupUntil
	}
	return until, err
}

func (a *connectorAdmission) SetupDeadline() time.Time { return a.setupUntil }

func (a *connectorAdmission) FinishSetup() error {
	b := a.peer.bound
	b.mu.Lock()
	if a.retiringLocked() || !a.admittedLocked() || a.ctx.Err() != nil || a.caller.Err() != nil || !a.peer.currentLocked() || !time.Now().Before(a.setupUntil) {
		b.mu.Unlock()
		return ErrPrivateStream
	}
	if _, err := a.guard.Current(); err != nil {
		b.mu.Unlock()
		return err
	}
	first := !a.readyLocked()
	a.state = readyConnectorAdmission{}
	allowed := a.audit
	b.mu.Unlock()
	if first {
		allowed.Outcome, allowed.Reason = "allowed", ""
		serviceaudit.Emit(b.audit, allowed)
	}
	return nil
}

type connectorOwnedConn struct {
	net.Conn
	admission *connectorAdmission
	prefix    *bytes.Reader
	readMu    sync.Mutex
}

func (c *connectorOwnedConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.prefix.Len() > 0 {
		return c.prefix.Read(p)
	}
	return c.Conn.Read(p)
}

func (c *connectorOwnedConn) Close() error { return c.admission.closeStream() }
func (c *connectorOwnedConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (a *connectorAdmission) forwardPeer() (result error) {
	p, b := a.peer, a.peer.bound
	binding := p.bindingSnapshot()
	visitorID, err := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	if err != nil {
		// the reservation still belongs to this worker until joined cleanup.
		a.cancel()
	}
	b.mu.Lock()
	a.audit = serviceaudit.Observation{ServiceID: binding.serviceID, ServiceKind: "service", RunID: binding.runID,
		RunNumber: int64(binding.number), PairID: binding.pairID, DeliveryGeneration: binding.generation, VisitorConnectionID: visitorID,
		SourceIP: binding.source.String(), EventType: "connection.open", Outcome: "denied", Reason: "authorization"}
	b.mu.Unlock()
	callerDone := make(chan struct{})
	stopCaller := context.AfterFunc(a.caller, func() { defer close(callerDone); a.stopAndClose() })
	defer func() {
		a.Stop()
		result = errors.Join(result, a.closeStream())
		if a.renewDone != nil {
			<-a.renewDone
		}
		if a.guard != nil {
			a.guard.Close()
		}
		if !stopCaller() {
			<-callerDone
		}
		if a.timer.Stop() {
			close(a.timerDone)
		}
		<-a.timerDone
		b.mu.Lock()
		ready := a.readyLocked()
		delete(p.streams, a)
		if !a.admittedLocked() {
			b.connectorPending--
		}
		if a.chargedLocked() {
			b.reservedStreams--
		}
		audit := a.audit
		a.state = releasedConnectorAdmission{}
		b.mu.Unlock()
		if ready {
			audit.EventType, audit.Outcome, audit.Reason = "connection.close", "closed", "closed"
			if result != nil {
				audit.Outcome, audit.Reason = "failed", "forwarding"
			}
		}
		serviceaudit.Emit(b.audit, audit)
	}()
	if err != nil {
		return err
	}
	if err := a.stream.SetDeadline(a.setupUntil); err != nil {
		return err
	}
	entry, initial, err := tunnelv1.ReadConnectorPeerVisitorOpening(a.stream)
	if err != nil {
		return err
	}
	view, enabled, _ := b.prepared.policy.Current()
	if !enabled || entry.MetadataRevision != uint64(b.prepared.metadataRevision) {
		return ErrPrivateStream
	}
	permission, err := visitortoken.VerifyConnectorPeerSession(entry, initial, binding.expected(), view, time.Now())
	if err != nil {
		return err
	}
	b.mu.Lock()
	a.audit.VisitorConnectionID = entry.VisitorConnectionID
	b.mu.Unlock()
	a.guard, err = b.prepared.policy.BindConnector(permission, binding.source, int64(entry.MetadataRevision), a.stopAndClose)
	if err != nil {
		return err
	}
	if err := a.guard.AllowRenewal(); err != nil {
		return err
	}
	b.mu.Lock()
	_, replay := p.seen[entry.VisitorConnectionID]
	valid := !a.retiringLocked() && a.ctx.Err() == nil && a.caller.Err() == nil && p.deliveryCurrentLocked() && p.network == binding.peerNetworkBinding && !replay && len(p.seen) < maxConnectorPeerHistory
	if valid {
		// valid acceptance spends history even when C or final handoff fails.
		p.seen[entry.VisitorConnectionID] = struct{}{}
		limit := b.streamCapacity
		if limit == 0 {
			limit = 64
		}
		valid = b.reservedStreams < limit
		if valid {
			b.reservedStreams++
			a.state = chargedConnectorAdmission{}
		}
	}
	if valid {
		_, err = a.guard.Current()
		valid = err == nil
	}
	if valid {
		if a.timer.Stop() {
			close(a.timerDone)
			valid = time.Now().Before(a.setupUntil)
		} else {
			valid = false
		}
	}
	if valid {
		a.state = admittedConnectorAdmission{}
		b.connectorPending--
		a.entry, a.permission = entry, permission
		a.renewals = make(chan connectorPermissionRenewal, 1)
		a.renewDone = make(chan struct{})
	}
	b.mu.Unlock()
	if !valid {
		return ErrPrivateStream
	}
	go a.renewPermissions()
	if _, err := a.CheckUse(a.ctx); err != nil {
		return err
	}
	// retain the original setup deadline while acknowledging admission. no
	// application protocol response or target work precedes this acceptance.
	if err := tunnelv1.WriteConnectorPeerVisitorAccepted(a.stream, entry.VisitorConnectionID); err != nil {
		return err
	}
	owned := &connectorOwnedConn{Conn: a.stream, admission: a, prefix: bytes.NewReader(initial)}
	if err := a.stream.SetDeadline(time.Time{}); err != nil {
		return err
	}
	visitorCtx := observability.WithVisitor(observability.ExtractWireTrace(a.ctx, entry.TraceContext), entry.VisitorConnectionID)
	return b.forwardManaged(visitorCtx, owned, servicestream.ConnectorVisitor{Admission: a}, "")
}

// dispatch never waits for policy installation or application IO. at most one
// update waits behind a visitor's active verification; overload retires only
// that visitor. unknown, pending and retired visitors cannot acquire authority.
type connectorPermissionRenewal struct {
	update    tunnelv1.ConnectorPermissionUpdate
	responder *tunnel.ConnectorPermissionResponder
	entry     tunnelv1.ConnectorPeerVisitorEntry
}

func (p *PeerSession) dispatchPermission(update tunnelv1.ConnectorPermissionUpdate, responder *tunnel.ConnectorPermissionResponder) {
	b := p.bound
	b.mu.Lock()
	var overloaded *connectorAdmission
	if p.currentLocked() {
		for a := range p.streams {
			if !a.admittedLocked() || a.retiringLocked() || a.entry.VisitorConnectionID != update.VisitorConnectionID {
				continue
			}
			if update.UpdateNumber <= a.lastUpdate {
				break
			}
			a.lastUpdate = update.UpdateNumber
			entry := a.entry
			if p.pending != nil && p.deliveryState != peerDeliveryRetired && update.DeliveryGeneration == p.pending.generation {
				entry.SourceIP = p.pending.source.String()
			}
			select {
			case a.renewals <- connectorPermissionRenewal{update: update, responder: responder, entry: entry}:
			default:
				a.retireLocked()
				overloaded = a
			}
			break
		}
	}
	b.mu.Unlock()
	if overloaded != nil {
		// cancellation is callback-free here; the owning worker closes and joins
		// the physical stream. a slow Close cannot stall the control decoder.
		overloaded.cancel()
	}
}

func (a *connectorAdmission) renewPermissions() {
	defer close(a.renewDone)
	for {
		select {
		case <-a.ctx.Done():
			return
		case renewal := <-a.renewals:
			entry := renewal.entry
			entry.DeliveryGeneration = renewal.update.DeliveryGeneration
			entry.Permission = renewal.update.Permission
			err := a.renewPermission(entry, a.permission)
			if errors.Is(err, tunnel.ErrConnectorPermissionStale) {
				if ackErr := renewal.responder.RespondStale(renewal.update); ackErr != nil {
					a.stopAndClose()
					return
				}
				continue
			}
			if err != nil {
				a.Stop()
			}
			if ackErr := renewal.responder.Respond(renewal.update, err == nil); ackErr != nil || err != nil {
				a.stopAndClose()
				return
			}
		}
	}
}

func (a *connectorAdmission) renewPermission(entry tunnelv1.ConnectorPeerVisitorEntry, original visitortoken.VerifiedPermission) error {
	// capture once: a newer snapshot or another update cannot reset the budget
	// while this proof waits for its policy revision to arrive.
	until, err := a.CheckUse(a.ctx)
	if err != nil {
		return err
	}
	for {
		if !until.After(time.Now()) {
			return ErrPrivateStream
		}
		view, enabled, _ := a.peer.bound.prepared.policy.Current()
		if !enabled {
			return ErrPrivateStream
		}
		b := a.peer.bound
		b.mu.Lock()
		binding := a.peer.bindingLocked()
		if a.peer.pending != nil && a.peer.deliveryState != peerDeliveryRetired && entry.DeliveryGeneration == a.peer.pending.generation {
			binding = *a.peer.pending
		}
		stale := entry.DeliveryGeneration < max(a.peer.highwater, a.peer.network.generation) || a.peer.deliveryState == peerDeliveryRetired && entry.DeliveryGeneration == a.peer.highwater ||
			entry.DeliveryGeneration == a.peer.network.generation && !a.peer.deliveryCurrentLocked()
		b.mu.Unlock()
		if stale {
			// a superseded proof grants no authority. the original guard remains
			// bounded by its existing deadline while a current proof follows.
			return a.stalePermission()
		}
		next, err := visitortoken.VerifyConnectorPeerRenewalProof(entry, nil, binding.expected(), view, time.Now())
		if err != nil {
			return err
		}
		if !next.SameIdentity(original) {
			return ErrPrivateStream
		}
		if !until.After(time.Now()) {
			return ErrPrivateStream
		}
		b.mu.Lock()
		current := a.peer.deliveryCurrentLocked() && a.peer.network.generation == entry.DeliveryGeneration && a.peer.network.source.String() == entry.SourceIP && !a.retiringLocked() && a.ctx.Err() == nil
		pending := a.peer.currentLocked() && a.peer.pending != nil && a.peer.deliveryState != peerDeliveryRetired && a.peer.pending.until.After(time.Now()) &&
			a.peer.pending.generation == entry.DeliveryGeneration && a.peer.pending.source.String() == entry.SourceIP && !a.retiringLocked() && a.ctx.Err() == nil
		stale = entry.DeliveryGeneration < max(a.peer.highwater, a.peer.network.generation) || a.peer.deliveryState == peerDeliveryRetired && entry.DeliveryGeneration == a.peer.highwater ||
			entry.DeliveryGeneration == a.peer.network.generation && !a.peer.deliveryCurrentLocked()
		if current {
			err = a.guard.Renew(next)
		}
		b.mu.Unlock()
		if !current && !pending {
			if stale {
				return a.stalePermission()
			}
			return ErrPrivateStream
		}
		if current && err == nil {
			return nil
		}
		currentView, _, _ := a.peer.bound.prepared.policy.Current()
		if current && next.Facts().VisitorPolicyRevision < currentView.VisitorPolicyRevision {
			// an independent snapshot can overtake an authentic in-flight proof.
			// it grants no renewal, but must not retire a still-current admission.
			// the original guard deadline bounds the wait for a current proof.
			return a.stalePermission()
		}
		if current && next.Facts().VisitorPolicyRevision <= view.VisitorPolicyRevision {
			return err
		}
		// control may issue a newer revision before the independent background
		// snapshot arrives. this proof grants nothing until that snapshot agrees;
		// only the existing guard's original bound can cover the wait.
		_, err = a.CheckUse(a.ctx)
		if err != nil {
			return err
		}
		if !until.After(time.Now()) {
			return ErrPrivateStream
		}
		timer := time.NewTimer(min(10*time.Millisecond, time.Until(until)))
		select {
		case <-a.ctx.Done():
			timer.Stop()
			return context.Cause(a.ctx)
		case <-timer.C:
		}
	}
}

func (a *connectorAdmission) stalePermission() error {
	if _, err := a.CheckUse(a.ctx); err != nil {
		return err
	}
	return tunnel.ErrConnectorPermissionStale
}
