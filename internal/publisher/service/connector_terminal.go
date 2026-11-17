package service

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var errConnectorAdmissionAbort = errors.New("connector admission aborted")

func connectorPeerStopError(err error) error {
	if muxsession.NormalSessionCloseOnly(err) {
		return nil
	}
	return serviceWorkerError(err, context.Canceled)
}

func connectorAdmissionRoutineError(err error) bool {
	var physical *muxsession.QUICTransportCloseError
	if errors.As(err, &physical) {
		return false
	}
	var localTLS *servicestream.VisitorTLSCallbackFailure
	if errors.As(err, &localTLS) {
		return false
	}
	// inspect connector provenance before the shared classifier can unwrap it.
	switch cause := err.(type) {
	case *connectorOpeningProofRefusal:
		return cause != nil && (cause.err == visitortoken.ErrToken || cause.err == visitortoken.ErrBinding)
	case *connectorRenewalProofRefusal:
		return cause != nil && cause.err == visitortoken.ErrBinding
	case *visitorlease.ConnectorPolicyRefusal:
		return cause != nil
	case *servicestream.VisitorHostnameRefusal:
		return cause != nil
	case *servicestream.VisitorProtocolRefusal:
		return cause != nil && cause.Unwrap() != nil
	case *servicestream.VisitorTLSCallbackFailure:
		return false
	case *servicestream.VisitorTLSIOFailure:
		return cause != nil && connectorAdmissionRoutineError(cause.Unwrap())
	case *tunnel.ConnectorControlFailure, *tunnel.SessionCleanupError:
		// required work cannot borrow a visitor-local refusal's provenance.
		return httpAdmissionRoutineError(err)
	case interface{ Unwrap() []error }:
		children := cause.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !connectorAdmissionRoutineError(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		child := cause.Unwrap()
		return child != nil && connectorAdmissionRoutineError(child)
	default:
		return httpAdmissionRoutineError(err)
	}
}

// replace only identified owned interruption leaves. physical-close markers
// and every unrelated operation/cleanup cause keep their original provenance.
func connectorAbortOperation(err error, ctx context.Context) error {
	if context.Cause(ctx) != errConnectorAdmissionAbort {
		return err
	}
	if err == context.Canceled {
		return errConnectorAdmissionAbort
	}
	switch cause := err.(type) {
	case *servicestream.SocketInterruption:
		if cause.StoppedBy(errConnectorAdmissionAbort) {
			return errConnectorAdmissionAbort
		}
	case *muxsession.QUICTransportCloseError:
		return err
	case *quic.StreamError:
		if cause != nil && !cause.Remote && cause.ErrorCode == 0 {
			return errConnectorAdmissionAbort
		}
	case interface{ Unwrap() []error }:
		var causes []error
		for _, child := range cause.Unwrap() {
			causes = append(causes, connectorAbortOperation(child, ctx))
		}
		return errors.Join(causes...)
	}
	return err
}

var _ tunnel.ConnectorPermissionControlHandlers = (*PeerSession)(nil)

type connectorAdmissionJoin struct {
	err                error
	completionConsumed bool
	abortRequested     bool
}

type connectorTerminalPhase struct {
	request   tunnelv1.ConnectorVisitorTerminalRequest
	responder *tunnel.ConnectorPermissionResponder
	result    *tunnelv1.ConnectorVisitorTerminalResult
	observed  bool
	resend    bool
	changed   chan struct{}
	done      chan struct{}
	end       tunnel.ConnectorTerminalEnd
	ctx       context.Context
	cancel    context.CancelCauseFunc
	timer     *time.Timer
	timerDone chan struct{}
	timerOnce sync.Once
	closing   bool
}

type connectorTerminalContext struct {
	context.Context
	until time.Time
}

func (c connectorTerminalContext) Deadline() (time.Time, bool) { return c.until, true }

func (p *PeerSession) controlScope() tunnelv1.ConnectorControlScope {
	return tunnelv1.ConnectorControlScope{
		ServiceID: p.identity.serviceID, ServiceRunID: p.identity.runID,
		RunNumber: p.identity.number, PublisherIdentityID: p.identity.publisherID,
		PairID: p.identity.pairID,
	}
}

// terminalBudgetLocked freezes authority before normal admission cleanup closes
// its guard. later renewal/rebind cannot enlarge this nonserving interval.
func (a *connectorAdmission) terminalBudgetLocked() time.Time {
	b, p := a.peer.bound, a.peer
	if a.terminalUntil.IsZero() {
		a.terminalUntil = time.Now().Add(5 * time.Second)
		if until, err := a.guard.Current(); err == nil {
			a.terminalUntil = peerDeadline(a.terminalUntil, until)
		} else if !a.authorityUntil.IsZero() {
			a.terminalUntil = peerDeadline(a.terminalUntil, a.authorityUntil)
		}
		if !p.owner.until.IsZero() {
			a.terminalUntil = peerDeadline(a.terminalUntil, p.owner.until)
		}
		if deadline, ok := a.caller.Deadline(); ok {
			a.terminalUntil = peerDeadline(a.terminalUntil, deadline)
		}
	}
	if !b.drainUntil.IsZero() {
		until := peerDeadline(a.terminalUntil, b.drainUntil)
		if until.Before(a.terminalUntil) && a.terminal != nil && !a.terminal.closing && a.terminal.timer.Stop() {
			a.terminal.timer.Reset(time.Until(until))
		}
		a.terminalUntil = until
	}
	if !p.stopUntil.IsZero() {
		a.terminalUntil = peerDeadline(a.terminalUntil, p.stopUntil)
	}
	return a.terminalUntil
}

func (p *PeerSession) terminalAdmissionLocked(key tunnelv1.ConnectorVisitorTerminalKey) *connectorAdmission {
	for a := range p.streams {
		if a.terminalKey == key {
			return a
		}
	}
	return nil
}

func (p *PeerSession) pruneAdmissionsLocked() {
	for a := range p.streams {
		if a.terminal != nil || a.joined == nil {
			continue
		}
		select {
		case <-a.joined:
			if p.terminalSealed || p.bound.terminalEntrySealed || !a.terminalBudgetLocked().After(time.Now()) {
				delete(p.streams, a)
			}
		default:
		}
	}
}

func signalConnectorTerminal(phase *connectorTerminalPhase) {
	close(phase.changed)
	phase.changed = make(chan struct{})
}

func (p *PeerSession) Terminal(request tunnelv1.ConnectorVisitorTerminalRequest, responder *tunnel.ConnectorPermissionResponder) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if responder == nil {
		return tunnel.ErrConnectorTerminalMismatch
	}
	b := p.bound
	b.mu.Lock()
	p.pruneAdmissionsLocked()
	a := p.terminalAdmissionLocked(request.Key)
	if a == nil {
		b.mu.Unlock()
		return tunnel.ErrConnectorTerminalRejected
	}
	if phase := a.terminal; phase != nil {
		if phase.request != request {
			b.mu.Unlock()
			return tunnel.ErrConnectorTerminalRejected
		}
		phase.resend = true
		signalConnectorTerminal(phase)
		b.mu.Unlock()
		return nil
	}
	if b.closed || b.terminalEntrySealed || p.terminalSealed || p.ownerRetired || p.ctx.Err() != nil ||
		request.Purpose == tunnelv1.ConnectorTerminalCompletion && (!a.readyLocked() || a.retiringLocked() || a.ctx.Err() != nil) {
		b.mu.Unlock()
		return tunnel.ErrConnectorTerminalRejected
	}
	// allocation order need not be arrival order. only another current phase
	// using this number is a collision; there is no greatest-seen-number fence.
	for other := range p.streams {
		if other.terminal != nil && other.terminal.request.TerminalNumber == request.TerminalNumber {
			b.mu.Unlock()
			return tunnel.ErrConnectorTerminalRejected
		}
	}
	if !a.terminalBudgetLocked().After(time.Now()) {
		b.mu.Unlock()
		return tunnel.ErrConnectorTerminalRejected
	}
	life, cancel := context.WithCancelCause(p.ctx)
	phase := &connectorTerminalPhase{
		request: request, responder: responder, changed: make(chan struct{}), done: make(chan struct{}),
		ctx: connectorTerminalContext{Context: life, until: a.terminalUntil}, cancel: cancel, timerDone: make(chan struct{}),
	}
	phase.timer = time.AfterFunc(time.Until(a.terminalUntil), func() {
		cancel(context.DeadlineExceeded)
		phase.timerOnce.Do(func() { close(phase.timerDone) })
	})
	a.terminal = phase
	b.terminalWorkers.Add(1)
	p.workers.Add(1)
	if request.Purpose == tunnelv1.ConnectorTerminalCompletion {
		a.completionConsumed = true
		a.complete.Do(func() { close(a.completed) })
	} else {
		a.abortRequested = true
		a.abortOwnsStop = !a.retiringLocked() && a.ctx.Err() == nil
		a.retireLocked()
	}
	b.mu.Unlock()
	go a.serveTerminal(phase)
	return nil
}

func (p *PeerSession) Observed(observed tunnelv1.ConnectorVisitorTerminalObserved) error {
	b := p.bound
	b.mu.Lock()
	defer b.mu.Unlock()
	a := p.terminalAdmissionLocked(observed.TerminalRequest().Key)
	if a == nil || a.terminal == nil {
		return tunnel.ErrConnectorTerminalMismatch
	}
	phase := a.terminal
	if observed.Kind != tunnelv1.ConnectorVisitorTerminalObservedKind || phase.result == nil ||
		observed.TerminalRequest() != phase.request || observed.Outcome != phase.result.Outcome ||
		observed.Outcome == tunnelv1.ConnectorTerminalRejected {
		return tunnel.ErrConnectorTerminalMismatch
	}
	phase.observed = true
	signalConnectorTerminal(phase)
	return nil
}

// Failed runs in the decoder's lifetime. it only publishes provenance and wakes
// the peer watch; cancellation, physical cleanup, and joins belong to owners.
func (p *PeerSession) Failed(failure *tunnel.ConnectorControlFailure) {
	p.observeSessionEnd(p.session)
	p.bound.mu.Lock()
	defer p.bound.mu.Unlock()
	if p.terminalEnd.Cause == tunnel.ConnectorTerminalPeerTerminated && failure != nil &&
		(failure.Err == io.EOF || muxsession.NormalSessionCloseOnly(failure.Err)) {
		return
	}
	p.controlFailed = true
	p.endLocked(tunnel.ConnectorTerminalEnd{Cause: tunnel.ConnectorTerminalLocalFailure, Err: failure})
}

func (p *PeerSession) observeSessionEnd(session muxsession.Session) {
	if session == nil {
		return
	}
	b := p.bound
	b.mu.Lock()
	defer b.mu.Unlock()
	if p.localSessionClose || p.controlFailed || p.ctx.Err() != nil {
		return
	}
	select {
	case <-session.Done():
		err := session.Err()
		var physical *muxsession.QUICTransportCloseError
		if !errors.As(err, &physical) && muxsession.NormalSessionCloseOnly(err) {
			err = nil
		}
		p.endLocked(tunnel.ConnectorTerminalEnd{Cause: tunnel.ConnectorTerminalPeerTerminated, Err: err})
	default:
	}
}

func (p *PeerSession) endLocked(end tunnel.ConnectorTerminalEnd) {
	if p.terminalEnd.Cause == "" {
		p.terminalEnd = end
	} else if end.Err != nil {
		p.terminalEnd.Err = errors.Join(p.terminalEnd.Err, end.Err)
	}
	p.terminalSealed = true
	close(p.changed)
	p.changed = make(chan struct{})
}

func (a *connectorAdmission) serveTerminal(phase *connectorTerminalPhase) {
	p, b := a.peer, a.peer.bound
	var result error
	defer func() {
		b.mu.Lock()
		phase.closing = true
		b.mu.Unlock()
		phase.cancel(context.Canceled)
		if phase.timer.Stop() {
			phase.timerOnce.Do(func() { close(phase.timerDone) })
		}
		<-phase.timerDone
		if !connectorAdmissionRoutineError(serviceWorkerError(a.joinedOutcome.err, errConnectorAdmissionAbort)) {
			p.stop()
		}
		b.mu.Lock()
		p.err = errors.Join(p.err, result)
		delete(p.streams, a)
		close(phase.done)
		p.workers.Done()
		b.terminalWorkers.Done()
		b.mu.Unlock()
	}()
	if phase.request.Purpose == tunnelv1.ConnectorTerminalAbort {
		if a.abortOwnsStop && a.abort != nil {
			a.abort(errConnectorAdmissionAbort)
		}
		a.stopAndClose()
	}
	// a spent deadline is not a joined socket/callback. never abandon entered
	// cleanup or wait for a group containing this terminal worker.
	<-a.joined
	b.mu.Lock()
	joined := a.joinedOutcome
	until := a.terminalBudgetLocked()
	end := p.terminalEnd
	b.mu.Unlock()
	if context.Cause(phase.ctx) == context.DeadlineExceeded {
		result = context.DeadlineExceeded
		phase.end = tunnel.ConnectorTerminalEnd{Cause: tunnel.ConnectorTerminalDeadline, Err: result}
		return
	}
	if end.Cause != "" {
		phase.end = end
		result = end.Err
		return
	}
	if !until.After(time.Now()) {
		phase.end = tunnel.ConnectorTerminalEnd{Cause: tunnel.ConnectorTerminalDeadline, Err: context.DeadlineExceeded}
		result = context.DeadlineExceeded
		return
	}
	outcome := tunnelv1.ConnectorTerminalFailed
	if phase.request.Purpose == tunnelv1.ConnectorTerminalCompletion && joined.completionConsumed && joined.err == nil ||
		phase.request.Purpose == tunnelv1.ConnectorTerminalAbort && serviceWorkerError(joined.err, errConnectorAdmissionAbort) == nil {
		outcome = tunnelv1.ConnectorTerminalAccepted
	}
	decision := tunnelv1.ConnectorVisitorTerminalResult{
		Kind:                tunnelv1.ConnectorVisitorTerminalResultKind,
		VisitorConnectionID: phase.request.Key.VisitorConnectionID, DeliveryGeneration: phase.request.Key.DeliveryGeneration,
		TerminalNumber: phase.request.TerminalNumber, Purpose: phase.request.Purpose, Outcome: outcome,
	}
	b.mu.Lock()
	phase.result = &decision
	b.mu.Unlock()
	written := false
	for {
		b.mu.Lock()
		until, changed, started := a.terminalBudgetLocked(), phase.changed, b.drainStarted
		if !b.drainUntil.IsZero() {
			started = nil
		}
		peerChanged, end, observed := p.changed, p.terminalEnd, phase.observed
		resend := phase.resend
		phase.resend = false
		b.mu.Unlock()
		if context.Cause(phase.ctx) == context.DeadlineExceeded {
			phase.end = tunnel.ConnectorTerminalEnd{Cause: tunnel.ConnectorTerminalDeadline, Err: context.DeadlineExceeded}
			result = errors.Join(result, context.DeadlineExceeded)
			return
		}
		if end.Cause != "" {
			phase.end, result = end, errors.Join(result, end.Err)
			return
		}
		if !until.After(time.Now()) {
			phase.end = tunnel.ConnectorTerminalEnd{Cause: tunnel.ConnectorTerminalDeadline, Err: context.DeadlineExceeded}
			result = errors.Join(result, context.DeadlineExceeded)
			return
		}
		if observed && written {
			phase.end = tunnel.ConnectorTerminalEnd{Cause: tunnel.ConnectorTerminalResultObserved}
			return
		}
		if !written || resend {
			err := phase.responder.Result(phase.ctx, decision)
			if err != nil {
				b.mu.Lock()
				end = p.terminalEnd
				b.mu.Unlock()
				if end.Cause == tunnel.ConnectorTerminalOwnerRetired || end.Cause == tunnel.ConnectorTerminalPeerTerminated {
					err = serviceWorkerError(err, context.Canceled)
					phase.end = end
					phase.end.Err = errors.Join(end.Err, err)
				} else if context.Cause(phase.ctx) == context.DeadlineExceeded {
					phase.end = tunnel.ConnectorTerminalEnd{Cause: tunnel.ConnectorTerminalDeadline, Err: errors.Join(err, context.DeadlineExceeded)}
				} else {
					phase.end = tunnel.ConnectorTerminalEnd{Cause: tunnel.ConnectorTerminalLocalFailure, Err: err}
				}
				result = errors.Join(result, err)
				return
			}
			written = true
			continue
		}
		timer := time.NewTimer(time.Until(until))
		select {
		case <-changed:
		case <-peerChanged:
		case <-p.ctx.Done():
		case <-started:
		case <-timer.C:
		}
		timer.Stop()
	}
}
