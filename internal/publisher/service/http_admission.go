package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	yamux "github.com/libp2p/go-yamux/v5"
	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const (
	maxHTTPPendingRelay  = 16
	maxHTTPPendingRun    = 32
	maxHTTPPendingSource = 8
)

// boundVisitor is the existing run registry's owned entry. only public HTTP
// visitors have staged admission; opaque streams keep their original lifetime.
type boundVisitor struct {
	net.Conn
	http *httpAdmission
}

func (v *boundVisitor) Close() error {
	if v.http != nil {
		return v.http.close()
	}
	return v.Conn.Close()
}

func (v *boundVisitor) SetDeadline(until time.Time) error {
	if a := v.http; a != nil {
		a.bound.mu.Lock()
		_, ready := a.state.(readyHTTPAdmission)
		if !ready && (until.IsZero() || a.setupUntil.Before(until)) {
			until = a.setupUntil
		}
		a.bound.mu.Unlock()
	}
	return v.Conn.SetDeadline(until)
}

// phases carry the actual charge, including while retirement is joining work.
// aggregate relay/source maps are accounting indexes, never visitor registries.
type httpAdmissionState interface{ httpAdmissionState() }

type unverifiedHTTPAdmission struct{}
type verifiedHTTPAdmission struct{ source netip.Prefix }
type finalHTTPAdmission struct{}
type readyHTTPAdmission struct{}
type retiringHTTPAdmission struct{ previous httpAdmissionState }
type releasedHTTPAdmission struct{}

func (unverifiedHTTPAdmission) httpAdmissionState() {}
func (verifiedHTTPAdmission) httpAdmissionState()   {}
func (finalHTTPAdmission) httpAdmissionState()      {}
func (readyHTTPAdmission) httpAdmissionState()      {}
func (retiringHTTPAdmission) httpAdmissionState()   {}
func (releasedHTTPAdmission) httpAdmissionState()   {}

type httpCapacityDecision struct {
	done   chan struct{}
	result error // published by closing done, after the capacity call joins
}

type httpAdmission struct {
	bound      *Bound
	visitor    *boundVisitor
	ref        tunnelv1.ServicePublisherConnectionRef
	ctx        context.Context
	cancel     context.CancelFunc
	setupUntil time.Time
	state      httpAdmissionState // protected by Bound.mu
	decision   *httpCapacityDecision
	timer      *time.Timer
	timerDone  chan struct{}
	stopOwner  func() bool
	ownerDone  chan struct{}
	closeOnce  sync.Once
	closeErr   error
	retireOnce sync.Once
	retireErr  error
	completed  chan struct{}
}

func (a *httpAdmission) chargedStateLocked() httpAdmissionState {
	if retiring, ok := a.state.(retiringHTTPAdmission); ok {
		return retiring.previous
	}
	return a.state
}

func (a *httpAdmission) pendingLocked() bool {
	switch a.chargedStateLocked().(type) {
	case unverifiedHTTPAdmission, verifiedHTTPAdmission:
		return true
	default:
		return false
	}
}

func (a *httpAdmission) retireLocked() {
	switch a.state.(type) {
	case retiringHTTPAdmission, releasedHTTPAdmission:
	default:
		a.state = retiringHTTPAdmission{previous: a.state}
	}
}

// reserveHTTP registers ownership before acceptance, without spending final
// visitor capacity. exact assignment checks precede every accounting change.
func (b *Bound) reserveHTTP(ctx context.Context, ref tunnelv1.ServicePublisherConnectionRef, stream net.Conn, header tunnelv1.ServiceForwardingHeader) (*boundVisitor, tunnelv1.ErrorCode) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if !b.currentLocked(ref) || !headerMatches(ref, header, now) {
		return nil, tunnelv1.StaleConnectionAssignment
	}
	if ctx == nil || ctx.Err() != nil || stream == nil || header.PublicService == nil || b.active[stream] != nil {
		return nil, tunnelv1.Unavailable
	}
	if !b.drainUntil.IsZero() || b.httpPending >= maxHTTPPendingRun || b.httpPendingRelays[ref.RelayServiceID] >= maxHTTPPendingRelay {
		return nil, tunnelv1.CapacityExceeded
	}
	if b.httpPendingRelays == nil {
		b.httpPendingRelays = make(map[string]int)
		b.httpPendingSources = make(map[netip.Prefix]int)
	}
	until := now.Add(10 * time.Second)
	for _, expiry := range []time.Time{header.ExpiresAt, header.LeaseExpiresAt} {
		if expiry.Before(until) {
			until = expiry
		}
	}
	life, cancel := context.WithCancel(ctx)
	v := &boundVisitor{Conn: stream}
	a := &httpAdmission{bound: b, visitor: v, ref: ref, ctx: life, cancel: cancel,
		setupUntil: until, state: unverifiedHTTPAdmission{}, timerDone: make(chan struct{}),
		ownerDone: make(chan struct{}), completed: make(chan struct{})}
	v.http = a
	b.active[stream] = v
	b.httpPending++
	b.httpPendingRelays[ref.RelayServiceID]++
	a.timer = time.AfterFunc(time.Until(until), func() {
		defer close(a.timerDone)
		_ = a.close()
	})
	a.stopOwner = context.AfterFunc(ctx, func() {
		defer close(a.ownerDone)
		_ = a.close()
	})
	return v, ""
}

// verifySource follows checkVisitorSource and its first-byte replay commit.
// neither unsigned metadata nor the claimed header alone can charge a source.
func (a *httpAdmission) verifySource(source netip.Addr) error {
	b := a.bound
	b.mu.Lock()
	defer b.mu.Unlock()
	network := trafficlimits.SourceNetwork(source)
	if _, pending := a.state.(unverifiedHTTPAdmission); !pending || !network.IsValid() ||
		a.ctx.Err() != nil || !b.currentLocked(a.ref) || !b.drainUntil.IsZero() || !time.Now().Before(a.setupUntil) {
		return ErrPrivateStream
	}
	if b.httpPendingSources[network] >= maxHTTPPendingSource {
		return &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
	}
	b.httpPendingSources[network]++
	a.state = verifiedHTTPAdmission{source: network}
	return nil
}

func (a *httpAdmission) releasePendingLocked() {
	b := a.bound
	b.httpPending--
	if b.httpPendingRelays[a.ref.RelayServiceID]--; b.httpPendingRelays[a.ref.RelayServiceID] == 0 {
		delete(b.httpPendingRelays, a.ref.RelayServiceID)
	}
	if phase, ok := a.chargedStateLocked().(verifiedHTTPAdmission); ok {
		if b.httpPendingSources[phase.source]--; b.httpPendingSources[phase.source] == 0 {
			delete(b.httpPendingSources, phase.source)
		}
	}
}

// reserveCapacity is entered only after the HTTP frontend's access and request
// checks. concurrent requests share one connection-owned operation; canceling
// an individual waiter cannot cancel it or cause a second ingress exchange.
func (a *httpAdmission) reserveCapacity(waiter context.Context, reserve func(context.Context) error) error {
	if err := context.Cause(waiter); err != nil {
		return err
	}
	b := a.bound
	b.mu.Lock()
	if a.decision == nil {
		decision := &httpCapacityDecision{done: make(chan struct{})}
		a.decision = decision
		_, verified := a.state.(verifiedHTTPAdmission)
		limit := b.streamCapacity
		if limit == 0 {
			limit = 64
		}
		switch {
		case !verified || a.ctx.Err() != nil || !b.currentLocked(a.ref) || !b.drainUntil.IsZero() || !time.Now().Before(a.setupUntil) || reserve == nil:
			decision.result = ErrPrivateStream
			close(decision.done)
		case b.reservedStreams >= limit:
			decision.result = &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
			close(decision.done)
		default:
			// phase is still verified under this same lock. move, rather than
			// refund, its setup charge into final physical visitor ownership.
			a.releasePendingLocked()
			b.reservedStreams++
			a.state = finalHTTPAdmission{}
			go a.decideCapacity(decision, reserve)
		}
	}
	decision := a.decision
	b.mu.Unlock()
	select {
	case <-waiter.Done():
		return context.Cause(waiter)
	case <-decision.done:
		return errors.Join(decision.result, context.Cause(waiter), context.Cause(a.ctx))
	}
}

func (a *httpAdmission) decideCapacity(decision *httpCapacityDecision, reserve func(context.Context) error) {
	call, cancel := context.WithDeadline(a.ctx, a.setupUntil)
	// reserve returns only after its owned wire cleanup joins.
	err := reserve(call)
	err = errors.Join(err, context.Cause(call))
	cancel()
	if err == nil {
		b := a.bound
		b.mu.Lock()
		joinTimer := false
		_, final := a.state.(finalHTTPAdmission)
		switch {
		case !final || a.ctx.Err() != nil || !b.currentLocked(a.ref):
			err = ErrPrivateStream
		case !time.Now().Before(a.setupUntil):
			err = context.DeadlineExceeded
		case !a.timer.Stop():
			// a firing timer owns its close. it cannot be disarmed by a late
			// acknowledgement, and must join before publishing that result.
			err = context.DeadlineExceeded
			joinTimer = true
		default:
			a.state = readyHTTPAdmission{}
			close(a.timerDone)
		}
		b.mu.Unlock()
		if joinTimer {
			<-a.timerDone
		}
		if err == nil {
			// TLS/header setup cannot clear this deadline before this point.
			err = a.visitor.Conn.SetDeadline(time.Time{})
			if err != nil {
				err = errors.Join(err, a.close())
			}
		}
	}
	decision.result = err
	close(decision.done)
}

// close interrupts the physical stream and fences new work, but never joins
// handlers or capacity work. only retire may release accounting.
func (a *httpAdmission) close() error {
	a.bound.mu.Lock()
	a.retireLocked()
	a.bound.mu.Unlock()
	a.cancel()
	a.closeOnce.Do(func() { a.closeErr = a.visitor.Conn.Close() })
	return a.closeErr
}

// retire runs after the serving owner has joined its handlers/target work.
// timer, cancellation callback, capacity exchange and physical close all join
// before the sole active entry and its actual remaining charge are removed.
func (a *httpAdmission) retire() error {
	a.retireOnce.Do(func() {
		a.retireErr = a.close()
		if !a.stopOwner() {
			<-a.ownerDone
		}
		if a.timer.Stop() {
			close(a.timerDone)
		}
		<-a.timerDone
		a.bound.mu.Lock()
		decision := a.decision
		a.bound.mu.Unlock()
		if decision != nil {
			<-decision.done
			a.retireErr = errors.Join(a.retireErr, decision.result)
		}
		b := a.bound
		b.mu.Lock()
		switch a.chargedStateLocked().(type) {
		case unverifiedHTTPAdmission, verifiedHTTPAdmission:
			a.releasePendingLocked()
		case finalHTTPAdmission, readyHTTPAdmission:
			b.reservedStreams--
		}
		a.state = releasedHTTPAdmission{}
		delete(b.active, a.visitor.Conn)
		close(a.completed)
		b.mu.Unlock()
	})
	return a.retireErr
}

// normal denial/transport termination stays stream-local. inspect every joined
// cause so cancellation cannot hide an independent physical cleanup failure.
func httpAdmissionRoutineError(err error) bool {
	if err == nil {
		return true
	}
	switch err {
	case ErrPrivateStream, context.Canceled, context.DeadlineExceeded, net.ErrClosed, muxsession.ErrClosed,
		io.EOF, io.ErrUnexpectedEOF, io.ErrClosedPipe, os.ErrDeadlineExceeded,
		syscall.EPIPE, syscall.ECONNRESET, syscall.ECONNABORTED:
		return true
	}
	switch cause := err.(type) {
	case *tunnel.ProtocolError:
		return true
	case *yamux.StreamError:
		return cause != nil && (cause.Remote || cause.ErrorCode == 0)
	case *quic.StreamError:
		return cause != nil && (cause.Remote || cause.ErrorCode == 0)
	case *quic.ApplicationError:
		return cause != nil && cause.Remote && cause.ErrorCode == 0
	case interface{ Unwrap() []error }:
		children := cause.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !httpAdmissionRoutineError(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		child := cause.Unwrap()
		return child != nil && httpAdmissionRoutineError(child)
	default:
		return false
	}
}
