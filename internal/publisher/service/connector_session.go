package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
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
	telemetryv1 "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const maxConnectorPeerOwners = 64
const maxConnectorPeerStreams = tunnel.MaxConnectorApplicationStreams

// PeerSession retains one exact control-delivered pair and its inner session.
// neither a carrier change nor a sibling connector changes this owner. a new
// pair/run needs a new owner; it cannot transfer the old owner's admissions.
type PeerSession struct {
	bound             *Bound
	identity          peerIdentity
	network           peerNetworkBinding
	lease             peerLease
	owner             peerLease
	pending           *PeerBinding
	deliveryState     peerDeliveryState
	highwater         int64
	installMu         sync.Mutex
	packets           *peer.Endpoint
	connectivity      *peer.Connectivity
	permissionGate    tunnel.ConnectorPermissionGate
	packetPaths       [2]*peer.CarrierSlot
	deliverySlots     [2]*Claimed
	ctx               context.Context
	cancel            context.CancelFunc
	seen              map[string]time.Time
	seenExpirations   connectorOpeningExpirations
	seenAt            time.Time
	streams           map[*connectorAdmission]struct{}
	serveOnce         sync.Once
	workers           sync.WaitGroup
	done              chan struct{}
	changed           chan struct{}
	replayUntil       time.Time
	ready             chan struct{}
	installedUntil    time.Time
	recoveryStarted   time.Time
	unbound           bool
	ownerRetired      bool
	retiredAt         time.Time
	retainedUntil     time.Time
	retirementUntil   time.Time
	preparationDone   chan struct{}
	stopPreparation   context.CancelFunc
	terminalSealed    bool
	controlFailed     bool
	terminalEnd       tunnel.ConnectorTerminalEnd
	stopUntil         time.Time
	err               error
	session           muxsession.Session
	localSessionClose bool
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
	b.prunePeerOwnersLocked(time.Now())
	p := b.connectorPeers[binding.pairID]
	if p != nil {
		if !p.unbound || p.ownerRetired || p.preparationDone == nil || p.ctx.Err() != nil {
			return nil, ErrPrivateStream
		}
	} else {
		if len(b.connectorPeers) >= maxConnectorPeerOwners {
			return nil, ErrPrivateStream
		}
		p = b.newPeerOwnerLocked(ctx, binding.pairID)
	}
	p.identity, p.network, p.lease, p.owner = binding.peerIdentity, binding.peerNetworkBinding, binding.peerLease, binding.peerLease
	p.highwater, p.deliveryState, p.unbound = binding.generation, peerDeliveryActive, false
	p.seen, p.streams = make(map[string]time.Time), make(map[*connectorAdmission]struct{})
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
	return !p.unbound && !p.ownerRetired && !p.controlFailed && !p.terminalSealed && p.replayUntil.IsZero() && p.ctx.Err() == nil && p.owner.until.After(time.Now()) &&
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
	if p.stopUntil.IsZero() {
		p.stopUntil = peerDeadline(time.Now().Add(5*time.Second), p.owner.until)
	}
	if p.terminalEnd.Cause == "" {
		p.endLocked(tunnel.ConnectorTerminalEnd{Cause: tunnel.ConnectorTerminalLocalFailure, Err: context.Canceled})
	}
	stopPreparation := p.stopPreparation
	b.mu.Unlock()
	p.cancel()
	if stopPreparation != nil {
		stopPreparation()
	}
}

func (p *PeerSession) Close() {
	p.stop()
	// closing a reservation before Serve consumes its single serving attempt.
	p.serveOnce.Do(func() { p.workers.Wait(); close(p.done) })
	<-p.done
}

// Serve owns setup, the renewable deadline watch, the retained inner session,
// and joined teardown. application streams still prove their own signed visits.
func (p *PeerSession) Serve(ctx context.Context) error {
	return p.serve(ctx, func() error { return p.serveRelayPackets(ctx) })
}

// setup and serving share one deadline watch and completion barrier. a setup
// failure has the same joined retirement as a terminal inner session.
func (p *PeerSession) serve(ctx context.Context, run func() error) (result error) {
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
		p.bound.mu.Lock()
		p.pruneAdmissionsLocked()
		if !p.recoveryStarted.IsZero() && p.deliverySlots[0] != nil {
			p.bound.telemetry.Record(telemetryv1.Recovery, clienttelemetry.Path(p.deliverySlots[0].transport), telemetryv1.Canceled, time.Since(p.recoveryStarted))
			p.recoveryStarted = time.Time{}
		}
		result = errors.Join(result, p.err)
		p.bound.mu.Unlock()
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

func (p *PeerSession) serveSession(session muxsession.Session) (result error) {
	if err := p.controlScope().Validate(); err != nil {
		return err
	}
	p.bound.mu.Lock()
	p.session = session
	p.bound.mu.Unlock()
	defer func() {
		p.observeSessionEnd(session)
		err := session.Close()
		var physical *muxsession.QUICTransportCloseError
		if errors.As(err, &physical) || !muxsession.NormalSessionCloseOnly(err) {
			result = errors.Join(result, err)
		}
	}()
	defer p.stop()
	setup, cancelSetup := context.WithTimeout(p.ctx, 10*time.Second)
	permissions, err := tunnel.AcceptConnectorPermissionControl(setup, session)
	cancelSetup()
	if err != nil {
		if muxsession.NormalSessionCloseOnly(err) {
			p.observeSessionEnd(session)
			return nil
		}
		if p.ctx.Err() != nil {
			return connectorPeerStopError(err)
		}
		return err
	}
	control, cancelControl := context.WithCancel(p.ctx)
	controlDone := make(chan error, 1)
	go func() {
		controlDone <- tunnel.ServeConnectorPermissionControl(control, permissions, p.controlScope(), p, &p.permissionGate)
	}()
	defer func() {
		p.observeSessionEnd(session)
		p.bound.mu.Lock()
		p.localSessionClose = true
		normalEnd := p.terminalEnd.Cause == tunnel.ConnectorTerminalPeerTerminated && p.terminalEnd.Err == nil
		p.bound.mu.Unlock()
		cancelControl()
		err := <-controlDone
		if normalEnd {
			err = serviceWorkerError(err, io.EOF)
		}
		result = errors.Join(result, connectorPeerStopError(err))
	}()
	for {
		stream, err := session.AcceptStream(p.ctx)
		if err != nil {
			p.observeSessionEnd(session)
			if p.ctx.Err() != nil {
				return connectorPeerStopError(err)
			}
			if muxsession.NormalSessionCloseOnly(err) {
				return nil
			}
			return err
		}
		a, err := p.reserve(p.ctx, stream)
		if err != nil {
			if closeErr := stream.Close(); !connectorAdmissionRoutineError(closeErr) {
				return closeErr
			}
			continue
		}
		go func() {
			defer p.workers.Done()
			err := a.forwardPeer()
			if a.joinedOutcome.abortRequested {
				err = serviceWorkerError(err, errConnectorAdmissionAbort)
			}
			if !connectorAdmissionRoutineError(err) {
				p.bound.mu.Lock()
				p.err = errors.Join(p.err, err)
				entered := a.terminal != nil
				p.bound.mu.Unlock()
				if !entered {
					p.stop()
				}
			}
		}()
	}
}

// connectorAdmission is the only connector stream-use issuer. its private construction
// retains the exact peer, pending charge, stream and verified guard. all mutable
// admission/owner/C state uses Bound.mu; pure guard entry then takes Lease.mu.
// the lease never calls service code while locked, so this order has no reverse
// edge. network I/O, cancellation, physical close and joins happen unlocked.
type connectorAdmission struct {
	peer               *PeerSession
	ctx                context.Context
	caller             context.Context
	cancel             context.CancelFunc
	stream             net.Conn
	guard              *visitorlease.ConnectorGuard
	entry              tunnelv1.ConnectorPeerVisitorEntry
	permission         visitortoken.VerifiedPermission
	renewals           chan connectorPermissionRenewal
	renewDone          chan struct{}
	lastUpdate         uint64
	state              connectorAdmissionState // protected by Bound.mu
	setupUntil         time.Time
	timer              *time.Timer
	timerDone          chan struct{}
	closeOnce          sync.Once
	closeErr           error
	audit              serviceaudit.Observation
	completed          chan struct{}
	complete           sync.Once
	finishOnce         sync.Once
	finishErr          error
	abort              context.CancelCauseFunc
	terminalKey        tunnelv1.ConnectorVisitorTerminalKey
	terminalUntil      time.Time
	authorityUntil     time.Time
	terminal           *connectorTerminalPhase
	completionConsumed bool
	abortRequested     bool
	abortOwnsStop      bool
	joined             chan struct{}
	joinedOutcome      connectorAdmissionJoin
	renewalErr         error
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
		limit = defaultStreamCapacity
	}
	p.pruneAdmissionsLocked()
	if caller.Err() != nil || !b.drainUntil.IsZero() || !p.deliveryCurrentLocked() || b.connectorPending >= min(limit, 4096) || len(p.streams) >= maxConnectorPeerStreams {
		return nil, ErrPrivateStream
	}
	life, abort := context.WithCancelCause(p.ctx)
	a := &connectorAdmission{peer: p, ctx: life, caller: caller, cancel: func() { abort(context.Canceled) }, abort: abort, stream: stream, state: reservedConnectorAdmission{}, setupUntil: time.Now().Add(10 * time.Second), timerDone: make(chan struct{}), completed: make(chan struct{}), joined: make(chan struct{})}
	a.timer = time.AfterFunc(time.Until(a.setupUntil), func() { defer close(a.timerDone); a.stopAndClose() })
	p.streams[a] = struct{}{}
	b.connectorPending++
	p.workers.Add(1)
	b.visitorWorkers.Add(1)
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

func (a *connectorAdmission) TargetAborting() bool {
	return context.Cause(a.ctx) == errConnectorAdmissionAbort
}

func (a *connectorAdmission) CheckUse(ctx context.Context) (time.Time, error) {
	b := a.peer.bound
	b.mu.Lock()
	defer b.mu.Unlock()
	return a.checkUseLocked(ctx)
}

func (a *connectorAdmission) checkUseLocked(ctx context.Context) (time.Time, error) {
	if a.abortOwnsStop && a.retiringLocked() || context.Cause(a.ctx) == errConnectorAdmissionAbort {
		return time.Time{}, errConnectorAdmissionAbort
	}
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
	if err == nil {
		a.authorityUntil = until
	}
	return until, err
}

func (a *connectorAdmission) SetupDeadline() time.Time { return a.setupUntil }

func (a *connectorAdmission) FinishSetup() error {
	b := a.peer.bound
	b.mu.Lock()
	if a.abortOwnsStop && a.retiringLocked() || context.Cause(a.ctx) == errConnectorAdmissionAbort {
		b.mu.Unlock()
		return errConnectorAdmissionAbort
	}
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
	n, err := c.Conn.Read(p)
	return n, connectorAbortOperation(err, c.admission)
}

func (c *connectorOwnedConn) Write(p []byte) (int, error) {
	if context.Cause(c.admission.ctx) == errConnectorAdmissionAbort {
		return 0, errConnectorAdmissionAbort
	}
	n, err := c.Conn.Write(p)
	return n, connectorAbortOperation(err, c.admission)
}

func (c *connectorOwnedConn) Close() error {
	return c.admission.closeStream()
}

// finishDelivery runs after forwarding, sockets, and callbacks have joined,
// before the stream owner stops admission. successful admissions retain capacity
// and packet carriers until exact return-delivery proof, including before drain.
func (a *connectorAdmission) finishDelivery(operation error) error {
	a.finishOnce.Do(func() {
		a.peer.bound.mu.Lock()
		a.terminalBudgetLocked()
		a.peer.bound.mu.Unlock()
		a.finishErr = a.closeStream()
		if operation != nil || a.finishErr != nil {
			return
		}
		b := a.peer.bound
		b.mu.Lock()
		// snapshot current authority once. permission or policy renewal cannot
		// extend a missing receipt's wait after application work has finished.
		until, err := a.checkUseLocked(a.ctx)
		until = peerDeadline(until, a.terminalBudgetLocked())
		started := b.drainStarted
		if !b.drainUntil.IsZero() {
			if b.drainUntil.Before(until) {
				until = b.drainUntil
			}
			started = nil
		}
		b.mu.Unlock()
		if err != nil {
			a.finishErr = errors.Join(err, context.Cause(a.ctx))
			return
		}
		// a request FIN is not proof of return delivery. an exact receipt grants
		// no access, renewal, or extension of this fixed completion deadline.
		timer := time.NewTimer(time.Until(until))
		defer timer.Stop()
		for {
			select {
			case <-a.completed:
				// receipt and drain can become ready together. enforce a published
				// deadline even when select chooses the receipt before Started.
				b.mu.Lock()
				if published := b.drainUntil; !published.IsZero() && published.Before(until) {
					until = published
				}
				b.mu.Unlock()
				if cause := context.Cause(a.ctx); cause != nil {
					a.finishErr = cause
				} else if !time.Now().Before(until) {
					a.finishErr = context.DeadlineExceeded
				}
				return
			case <-a.ctx.Done():
				a.finishErr = context.Cause(a.ctx)
				return
			case <-started:
				// the run owner publishes its original deadline before this signal.
				// late publication can only shorten the captured authority bound.
				b.mu.Lock()
				published := b.drainUntil
				b.mu.Unlock()
				if published.Before(until) {
					until = published
					timer.Reset(time.Until(until))
				}
				started = nil
			case <-timer.C:
				a.finishErr = context.DeadlineExceeded
				return
			}
		}
	})
	return a.finishErr
}
func (c *connectorOwnedConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.ErrUnsupported
}

// only the initial verifier's exact token/binding refusal is admission-local.
// physical cleanup remains a separate cause in the owning worker's joined result.
type connectorOpeningProofRefusal struct{ err error }

func (e *connectorOpeningProofRefusal) Error() string { return e.err.Error() }
func (e *connectorOpeningProofRefusal) Unwrap() error { return e.err }

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
		b.mu.Lock()
		a.terminalBudgetLocked()
		b.mu.Unlock()
		a.Stop()
		result = errors.Join(result, a.closeStream())
		if a.renewDone != nil {
			<-a.renewDone
		}
		result = errors.Join(result, a.renewalErr)
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
		if a.terminalKey.Validate() != nil {
			delete(p.streams, a)
		}
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
		b.mu.Lock()
		a.joinedOutcome = connectorAdmissionJoin{err: result, completionConsumed: a.completionConsumed, abortRequested: a.abortRequested}
		close(a.joined)
		if a.terminal == nil && (p.terminalSealed || b.terminalEntrySealed) {
			delete(p.streams, a)
		}
		b.visitorWorkers.Done()
		b.mu.Unlock()
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
	permission, err := visitortoken.VerifyConnectorPeerRenewalProof(entry, initial, binding.expected(), view, time.Now())
	if err != nil {
		if err == visitortoken.ErrToken || err == visitortoken.ErrBinding {
			return &connectorOpeningProofRefusal{err: err}
		}
		return err
	}
	// control can issue an opening against the just-committed grant before its
	// notice reaches this publisher. only a verified proof can wait for the
	// background owner, using the original setup budget and no on-demand read.
	if revision := permission.Facts().VisitorPolicyRevision; revision > view.VisitorPolicyRevision {
		wait, cancel := context.WithDeadline(a.ctx, a.setupUntil)
		err := b.prepared.policy.WaitRevision(wait, revision)
		cancel()
		if err != nil {
			return err
		}
		view, enabled, _ = b.prepared.policy.Current()
		if !enabled {
			return visitortoken.ErrPolicy
		}
	}
	if err := visitortoken.CheckCurrent(permission, view, time.Now()); err != nil {
		if err == visitortoken.ErrToken || err == visitortoken.ErrBinding {
			return &connectorOpeningProofRefusal{err: err}
		}
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
	valid := !a.retiringLocked() && a.ctx.Err() == nil && a.caller.Err() == nil && p.deliveryCurrentLocked() && p.network == binding.peerNetworkBinding &&
		p.rememberOpeningLocked(entry.VisitorConnectionID, view.AuthorityTime(time.Now()), permission.Facts().ExpiresAt)
	if valid {
		// valid acceptance spends history even when C or final handoff fails.
		limit := b.streamCapacity
		if limit == 0 {
			limit = defaultStreamCapacity
		}
		valid = b.reservedStreams < limit
		if valid {
			b.reservedStreams++
			a.state = chargedConnectorAdmission{}
		}
	}
	if valid {
		until, checkErr := a.guard.Current()
		err = checkErr
		valid = err == nil
		if valid {
			a.authorityUntil = peerDeadline(until, p.owner.until)
		}
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
		a.terminalKey = tunnelv1.ConnectorVisitorTerminalKey{VisitorConnectionID: entry.VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration}
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
	defer func() { result = errors.Join(result, owned.Close()) }()
	if err := a.stream.SetDeadline(time.Time{}); err != nil {
		return err
	}
	visitorCtx := observability.WithVisitor(observability.ExtractWireTrace(a.ctx, entry.TraceContext), entry.VisitorConnectionID)
	err = b.forwardManaged(visitorCtx, owned, servicestream.ConnectorVisitor{Admission: a, HTTPProof: a}, "", a.finishDelivery)
	return connectorAbortOperation(err, a)
}

// dispatch never waits for policy installation or application IO. at most one
// update waits behind a visitor's active verification; overload retires only
// that visitor. unknown, pending and retired visitors cannot acquire authority.
type connectorPermissionRenewal struct {
	update    tunnelv1.ConnectorPermissionUpdate
	responder *tunnel.ConnectorPermissionResponder
	entry     tunnelv1.ConnectorPeerVisitorEntry
}

// only an acknowledged renewal verifier's exact proof refusal is admission-local.
// retain its cause without marking ack or physical cleanup failures routine.
type connectorRenewalProofRefusal struct{ err error }

func (e *connectorRenewalProofRefusal) Error() string { return e.err.Error() }
func (e *connectorRenewalProofRefusal) Unwrap() error { return e.err }

func (p *PeerSession) Update(update tunnelv1.ConnectorPermissionUpdate, responder *tunnel.ConnectorPermissionResponder) error {
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
	return nil
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
			b := a.peer.bound
			b.mu.Lock()
			original := a.permission
			b.mu.Unlock()
			until, checkErr := a.CheckUse(a.ctx)
			if checkErr != nil {
				return
			}
			ack, cancel := context.WithDeadline(a.peer.ctx, until)
			err := a.renewPermission(entry, original)
			if err == tunnel.ErrConnectorPermissionStale {
				ackErr := renewal.responder.RespondStale(ack, renewal.update)
				cancel()
				if ackErr != nil {
					a.renewalErr = ackErr
					a.stopAndClose()
					return
				}
				continue
			}
			if err != nil {
				a.Stop()
			}
			ackErr := renewal.responder.Respond(ack, renewal.update, err == nil)
			cancel()
			if ackErr != nil || err != nil {
				if err == visitortoken.ErrBinding && ackErr == nil {
					err = &connectorRenewalProofRefusal{err: err}
				}
				a.renewalErr = errors.Join(err, ackErr)
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
		b.mu.Lock()
		a.peer.pruneOpeningHistoryLocked(view.AuthorityTime(time.Now()))
		a.peer.extendOpeningLocked(entry.VisitorConnectionID, next.Facts().ExpiresAt)
		if !until.After(time.Now()) {
			b.mu.Unlock()
			return ErrPrivateStream
		}
		current := a.peer.deliveryCurrentLocked() && a.peer.network.generation == entry.DeliveryGeneration && a.peer.network.source.String() == entry.SourceIP && !a.retiringLocked() && a.ctx.Err() == nil
		pending := a.peer.currentLocked() && a.peer.pending != nil && a.peer.deliveryState != peerDeliveryRetired && a.peer.pending.until.After(time.Now()) &&
			a.peer.pending.generation == entry.DeliveryGeneration && a.peer.pending.source.String() == entry.SourceIP && !a.retiringLocked() && a.ctx.Err() == nil
		stale = entry.DeliveryGeneration < max(a.peer.highwater, a.peer.network.generation) || a.peer.deliveryState == peerDeliveryRetired && entry.DeliveryGeneration == a.peer.highwater ||
			entry.DeliveryGeneration == a.peer.network.generation && !a.peer.deliveryCurrentLocked()
		if current {
			err = a.guard.Renew(next)
			if err == nil {
				a.entry, a.permission = entry, next
			}
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
