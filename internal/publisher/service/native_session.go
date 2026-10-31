package service

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const maxNativePeerOwners = 64
const maxNativePeerHistory = 4096
const maxNativePeerStreams = 64

// PeerSession retains one exact control-delivered pair and its inner session.
// neither a carrier change nor a sibling connector changes this owner. a new
// pair/run needs a new owner; it cannot transfer the old owner's admissions.
type PeerSession struct {
	bound         *Bound
	binding       PeerBinding
	ctx           context.Context
	cancel        context.CancelFunc
	closed        bool
	seen          map[string]struct{}
	streams       map[*nativeAdmission]struct{}
	session       muxsession.Session
	started       bool
	serve         sync.WaitGroup
	workers       sync.WaitGroup
	watchDone     chan struct{}
	changed       chan struct{}
	replayUntil   time.Time
	packetStarted bool
	packetReady   chan struct{}
	packets       sync.WaitGroup
	prepared      bool
}

func (b *Bound) BindPeer(ctx context.Context, binding PeerBinding) (*PeerSession, error) {
	if b == nil || b.boundState == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrPrivateStream
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.peerCurrentLocked(binding) || !b.peerRelaysCurrentLocked(binding) {
		return nil, ErrPrivateStream
	}
	for id, old := range b.nativePeers {
		if old.closed && !old.replayUntil.After(time.Now()) {
			delete(b.nativePeers, id)
		}
	}
	if b.nativePeers[binding.pairID] != nil || len(b.nativePeers) >= maxNativePeerOwners {
		return nil, ErrPrivateStream
	}
	if b.nativePeers == nil {
		b.nativePeers = make(map[string]*PeerSession)
	}
	life, cancel := context.WithCancel(ctx)
	p := &PeerSession{bound: b, binding: binding, ctx: life, cancel: cancel, seen: make(map[string]struct{}), streams: make(map[*nativeAdmission]struct{}), watchDone: make(chan struct{}), changed: make(chan struct{}), packetReady: make(chan struct{})}
	b.nativePeers[binding.pairID] = p
	go p.watch()
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
	old := p.binding
	valid := p.currentLocked() && b.peerCurrentLocked(binding) && b.peerRelaysCurrentLocked(binding) &&
		binding.pairID == old.pairID && binding.serviceID == old.serviceID && binding.runID == old.runID &&
		binding.publisherID == old.publisherID && binding.number == old.number && binding.generation == old.generation &&
		binding.delivery == old.delivery && binding.key == old.key && binding.source == old.source && binding.subject == old.subject && binding.relays == old.relays
	if !valid {
		return ErrPrivateStream
	}
	p.binding = binding
	close(p.changed)
	p.changed = make(chan struct{})
	return nil
}

func (p *PeerSession) currentLocked() bool {
	return !p.closed && p.ctx.Err() == nil && p.bound.nativePeers[p.binding.pairID] == p && p.bound.peerCurrentLocked(p.binding) && p.bound.peerRelaysCurrentLocked(p.binding)
}

func (p *PeerSession) watch() {
	defer close(p.watchDone)
	defer p.stop()
	for {
		p.bound.mu.Lock()
		current := p.currentLocked()
		until, changed := p.binding.until, p.changed
		p.bound.mu.Unlock()
		if !current {
			return
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
	return p.binding
}

func (p *PeerSession) stop() {
	b := p.bound
	b.mu.Lock()
	p.closed = true
	if p.replayUntil.IsZero() {
		p.replayUntil = time.Now().Add(5 * time.Minute)
	}
	stream := p.session
	admissions := make([]*nativeAdmission, 0, len(p.streams))
	for a := range p.streams {
		a.retiring = true
		admissions = append(admissions, a)
	}
	b.mu.Unlock()
	p.cancel()
	if stream != nil {
		_ = stream.Close()
	}
	for _, a := range admissions {
		a.cancel()
		_ = a.closeStream()
	}
}

func (p *PeerSession) Close() {
	p.stop()
	<-p.watchDone
	p.packets.Wait()
	p.serve.Wait()
	p.workers.Wait()
}

// Serve installs the actual retained inner-QUIC consumer. only control-delivered
// bindings reach BindPeer; each application still proves its own signed visit.
// this operation owns and joins the supplied inner session, not its carriers.
func (p *PeerSession) Serve(ctx context.Context, session muxsession.Session) error {
	if p == nil || session == nil {
		return ErrPrivateStream
	}
	b := p.bound
	b.mu.Lock()
	if p.started || ctx.Err() != nil || !p.currentLocked() {
		b.mu.Unlock()
		_ = session.Close()
		return ErrPrivateStream
	}
	p.session, p.started = session, true
	p.serve.Add(1)
	b.mu.Unlock()
	defer p.serve.Done()
	defer p.stop()
	callerDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(callerDone); p.stop() })
	defer func() {
		if !stop() {
			<-callerDone
		}
	}()
	for {
		stream, err := session.AcceptStream(p.ctx)
		if err != nil {
			if p.ctx.Err() != nil || ctx.Err() != nil || errors.Is(err, muxsession.ErrClosed) {
				return nil
			}
			return err
		}
		a, err := p.reserve(ctx, stream)
		if err != nil {
			_ = stream.Close()
			continue
		}
		go func() { defer p.workers.Done(); _ = a.forwardPeer() }()
	}
}

// nativeAdmission is the only native stream-use issuer. its private construction
// retains the exact peer, pending charge, stream and verified guard. all mutable
// admission/owner/C state uses Bound.mu; pure guard entry then takes Lease.mu.
// the lease never calls service code while locked, so this order has no reverse
// edge. network I/O, cancellation, physical close and joins happen unlocked.
type nativeAdmission struct {
	peer                                           *PeerSession
	ctx                                            context.Context
	caller                                         context.Context
	cancel                                         context.CancelFunc
	stream                                         net.Conn
	guard                                          *visitorlease.NativeGuard
	retiring, admitted, authorized, pending, ready bool
	setupUntil                                     time.Time
	timer                                          *time.Timer
	timerDone                                      chan struct{}
	timerStopped                                   bool
	closeOnce                                      sync.Once
	closeErr                                       error
	audit                                          serviceaudit.Observation
}

func (p *PeerSession) reserve(caller context.Context, stream net.Conn) (*nativeAdmission, error) {
	b := p.bound
	b.mu.Lock()
	defer b.mu.Unlock()
	limit := b.streamCapacity
	if limit == 0 {
		limit = 64
	}
	if caller.Err() != nil || !p.currentLocked() || b.nativePending >= min(limit, 4096) || len(p.streams) >= maxNativePeerStreams {
		return nil, ErrPrivateStream
	}
	life, cancel := context.WithCancel(p.ctx)
	a := &nativeAdmission{peer: p, ctx: life, caller: caller, cancel: cancel, stream: stream, pending: true, setupUntil: time.Now().Add(10 * time.Second), timerDone: make(chan struct{})}
	a.timer = time.AfterFunc(time.Until(a.setupUntil), func() { defer close(a.timerDone); a.stopAndClose() })
	p.streams[a] = struct{}{}
	b.nativePending++
	p.workers.Add(1)
	return a, nil
}

func (a *nativeAdmission) Stop() {
	b := a.peer.bound
	b.mu.Lock()
	a.retiring = true
	b.mu.Unlock()
	a.cancel()
}

func (a *nativeAdmission) closeStream() error {
	a.closeOnce.Do(func() { a.closeErr = a.stream.Close() })
	return a.closeErr
}

func (a *nativeAdmission) stopAndClose() { a.Stop(); _ = a.closeStream() }

func (a *nativeAdmission) CheckUse(ctx context.Context) (time.Time, error) {
	b := a.peer.bound
	b.mu.Lock()
	defer b.mu.Unlock()
	if a.retiring || !a.admitted || !a.ready && !time.Now().Before(a.setupUntil) || a.ctx.Err() != nil || a.caller.Err() != nil || ctx.Err() != nil || !a.peer.currentLocked() {
		return time.Time{}, ErrPrivateStream
	}
	until, err := a.guard.Current()
	if a.peer.binding.until.Before(until) {
		until = a.peer.binding.until
	}
	if !a.ready && a.setupUntil.Before(until) {
		until = a.setupUntil
	}
	return until, err
}

func (a *nativeAdmission) SetupDeadline() time.Time { return a.setupUntil }

func (a *nativeAdmission) FinishSetup() error {
	b := a.peer.bound
	b.mu.Lock()
	if a.retiring || !a.admitted || a.ctx.Err() != nil || a.caller.Err() != nil || !a.peer.currentLocked() || !time.Now().Before(a.setupUntil) {
		b.mu.Unlock()
		return ErrPrivateStream
	}
	if _, err := a.guard.Current(); err != nil {
		b.mu.Unlock()
		return err
	}
	first := !a.ready
	a.ready = true
	b.mu.Unlock()
	if first {
		allowed := a.audit
		allowed.Outcome, allowed.Reason = "allowed", ""
		serviceaudit.Emit(b.audit, allowed)
	}
	return nil
}

type nativeOwnedConn struct {
	net.Conn
	admission *nativeAdmission
}

func (c *nativeOwnedConn) Close() error { return c.admission.closeStream() }
func (c *nativeOwnedConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (a *nativeAdmission) forwardPeer() (result error) {
	p, b := a.peer, a.peer.bound
	binding := p.bindingSnapshot()
	visitorID, err := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	if err != nil {
		// the reservation still belongs to this worker until joined cleanup.
		a.cancel()
	}
	a.audit = serviceaudit.Observation{ServiceID: binding.serviceID, ServiceKind: "service", RunID: binding.runID,
		RunNumber: int64(binding.number), PairID: binding.pairID, VisitorConnectionID: visitorID,
		SourceIP: binding.source.String(), EventType: "connection.open", Outcome: "denied", Reason: "authorization"}
	var reader *tunnel.NativeRequestReader
	callerDone := make(chan struct{})
	stopCaller := context.AfterFunc(a.caller, func() { defer close(callerDone); a.stopAndClose() })
	defer func() {
		a.Stop()
		result = errors.Join(result, a.closeStream())
		if reader != nil {
			result = errors.Join(result, reader.Finish())
		}
		if a.guard != nil {
			a.guard.Close()
		}
		if !stopCaller() {
			<-callerDone
		}
		if !a.timerStopped && !a.timer.Stop() {
			<-a.timerDone
		}
		b.mu.Lock()
		ready := a.ready
		delete(p.streams, a)
		if a.pending {
			b.nativePending--
		}
		if a.authorized {
			b.reservedStreams--
		}
		b.mu.Unlock()
		if ready {
			a.audit.EventType, a.audit.Outcome, a.audit.Reason = "connection.close", "closed", "closed"
			if result != nil {
				a.audit.Outcome, a.audit.Reason = "failed", "forwarding"
			}
		}
		serviceaudit.Emit(b.audit, a.audit)
	}()
	if err != nil {
		return err
	}
	if err := a.stream.SetDeadline(a.setupUntil); err != nil {
		return err
	}
	entry, initial, err := tunnelv1.ReadNativePeerVisitorOpening(a.stream)
	if err != nil {
		return err
	}
	view, enabled, _ := b.prepared.policy.Current()
	if !enabled || entry.MetadataRevision != uint64(b.prepared.metadataRevision) {
		return ErrPrivateStream
	}
	permission, err := visitortoken.VerifyNativePeerSession(entry, initial, binding.expected(), view, time.Now())
	if err != nil {
		return err
	}
	a.audit.VisitorConnectionID = entry.VisitorConnectionID
	a.guard, err = b.prepared.policy.BindNative(permission, binding.source, int64(entry.MetadataRevision), a.stopAndClose)
	if err != nil {
		return err
	}
	if err := a.guard.AllowRenewal(); err != nil {
		return err
	}
	b.mu.Lock()
	_, replay := p.seen[entry.VisitorConnectionID]
	valid := !a.retiring && a.ctx.Err() == nil && a.caller.Err() == nil && p.currentLocked() && !replay && len(p.seen) < maxNativePeerHistory
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
			a.authorized = true
		}
	}
	if valid {
		_, err = a.guard.Current()
		valid = err == nil
	}
	if valid {
		a.timerStopped = a.timer.Stop()
		valid = a.timerStopped && time.Now().Before(a.setupUntil)
	}
	if valid {
		a.admitted = true
		a.pending = false
		b.nativePending--
	}
	b.mu.Unlock()
	if !valid {
		return ErrPrivateStream
	}
	owned := &nativeOwnedConn{Conn: a.stream, admission: a}
	reader = tunnel.NewNativeRequestReader(owned, initial, func(proof tunnelv1.NativeVisitorPermission) error {
		nextEntry := entry
		nextEntry.Permission = proof
		err := a.renewPermission(nextEntry, permission)
		if err != nil {
			a.stopAndClose()
		}
		return err
	})
	if err := a.stream.SetDeadline(time.Time{}); err != nil {
		return err
	}
	visitorCtx := observability.WithVisitor(observability.ExtractWireTrace(a.ctx, entry.TraceContext), entry.VisitorConnectionID)
	return b.forwardManaged(visitorCtx, reader, publisher.NativeVisitor{Admission: a}, "")
}

func (a *nativeAdmission) renewPermission(entry tunnelv1.NativePeerVisitorEntry, original visitortoken.VerifiedPermission) error {
	for {
		view, enabled, _ := a.peer.bound.prepared.policy.Current()
		if !enabled {
			return ErrPrivateStream
		}
		binding := a.peer.bindingSnapshot()
		next, err := visitortoken.VerifyNativePeerRenewalProof(entry, nil, binding.expected(), view, time.Now())
		if err != nil {
			return err
		}
		if !next.SameIdentity(original) {
			return ErrPrivateStream
		}
		err = a.guard.Renew(next)
		if err == nil || next.Facts().VisitorPolicyRevision <= view.VisitorPolicyRevision {
			return err
		}
		// control may issue a newer revision before the independent background
		// snapshot arrives. this proof grants nothing until that snapshot agrees;
		// only the existing guard's original bound can cover the wait.
		until, err := a.CheckUse(a.ctx)
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
