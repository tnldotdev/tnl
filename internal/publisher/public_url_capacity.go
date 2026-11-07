package publisher

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// pending setups are bounded per trusted relay service and verified source,
// independently of the run's authorized visitor connections.
const PendingSetupsPerRelay = 16
const PendingSetupsPerSource = 8

// publicVisitorAdmission belongs to a connection, not an HTTP request. the run
// owns all counters, including retiring sessions from the same relay service.
type publicVisitorAdmission struct {
	run        *PublicURLServer
	live       *livePublisherSession
	stream     net.Conn
	connection *doneConn
	phase      publicVisitorPhase // protected by run.mu
	timer      *time.Timer
	timerDone  chan struct{}
	expiresAt  time.Time
	closeOnce  sync.Once
	done       chan struct{}
}

// capacity has one owner from reservation through physical close. a stopped
// setup retains its pending source/relay charges until retire joins the close.
type publicVisitorPhase interface{ publicVisitorPhase() }
type unverifiedPublicSetup struct{}
type verifiedPublicSetup struct{ source netip.Prefix }
type committedPublicSetup struct{}
type promotedPublicSetup struct{}
type stoppedPublicSetup struct{ previous publicVisitorPhase }
type retiredPublicSetup struct{}

func (unverifiedPublicSetup) publicVisitorPhase() {}
func (verifiedPublicSetup) publicVisitorPhase()   {}
func (committedPublicSetup) publicVisitorPhase()  {}
func (promotedPublicSetup) publicVisitorPhase()   {}
func (stoppedPublicSetup) publicVisitorPhase()    {}
func (retiredPublicSetup) publicVisitorPhase()    {}

func (a *publicVisitorAdmission) chargedPhaseLocked() publicVisitorPhase {
	if stopped, ok := a.phase.(stoppedPublicSetup); ok {
		return stopped.previous
	}
	return a.phase
}

func (a *publicVisitorAdmission) admittedLocked() bool {
	switch a.chargedPhaseLocked().(type) {
	case committedPublicSetup, promotedPublicSetup:
		return true
	default:
		return false
	}
}

func (a *publicVisitorAdmission) sourceLocked() netip.Prefix {
	if verified, ok := a.chargedPhaseLocked().(verifiedPublicSetup); ok {
		return verified.source
	}
	return netip.Prefix{}
}

func (r *PublicURLServer) reservePublicSetup(live *livePublisherSession, stream net.Conn) (*publicVisitorAdmission, tunnelv1.ErrorCode) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.draining || live == nil || live.ctx.Err() != nil || r.sessions[live.ref.ConnectionSlot] != live {
		return nil, tunnelv1.Unavailable
	}
	domain := live.ref.RelayServiceID
	if r.pendingStreams >= publisherConnectionCount*PendingSetupsPerRelay || r.pendingRelays[domain] >= PendingSetupsPerRelay {
		return nil, tunnelv1.CapacityExceeded
	}
	if r.pendingRelays == nil {
		r.pendingRelays = make(map[string]int)
	}
	r.pendingRelays[domain]++
	r.pendingStreams++
	r.handlers.Add(1)
	live.visitors.Add(1)
	a := &publicVisitorAdmission{run: r, live: live, stream: stream, connection: newDoneConn(stream), phase: unverifiedPublicSetup{}, timerDone: make(chan struct{}), done: make(chan struct{}), expiresAt: time.Now().Add(visitorPromotionTimeout)}
	r.streams[stream] = a
	a.timer = time.AfterFunc(visitorPromotionTimeout, func() {
		defer close(a.timerDone)
		_ = a.connection.Close()
	})
	return a, ""
}

// charge a source only after verifying ingress's signed metadata. the run owns
// this allowance across both relays, including their retiring connections.
func (a *publicVisitorAdmission) authenticateSource(stream tunnelv1.VisitorStreamHeader, header proxyproto.Header) error {
	r := a.run
	if err := r.authenticateVisitorSource(stream, header); err != nil {
		return err
	}
	source := trafficlimits.SourceNetwork(header.Source.Addr())
	if !source.IsValid() {
		return visitortoken.ErrVisitorSource
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !a.currentLocked() {
		return net.ErrClosed
	}
	if _, unverified := a.phase.(unverifiedPublicSetup); !unverified {
		return net.ErrClosed
	}
	if r.draining || !time.Now().Before(a.expiresAt) || r.pendingSources[source] >= PendingSetupsPerSource {
		return &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
	}
	if r.pendingSources == nil {
		r.pendingSources = make(map[netip.Prefix]int)
	}
	r.pendingSources[source]++
	a.phase = verifiedPublicSetup{source: source}
	return nil
}

func (a *publicVisitorAdmission) leavePendingLocked() {
	r := a.run
	domain := a.live.ref.RelayServiceID
	r.pendingStreams--
	r.pendingRelays[domain]--
	if r.pendingRelays[domain] == 0 {
		delete(r.pendingRelays, domain)
	}
	if source := a.sourceLocked(); source.IsValid() {
		r.pendingSources[source]--
		if r.pendingSources[source] == 0 {
			delete(r.pendingSources, source)
		}
	}
}

// commit is called only after this request's authorization and ownership check.
// it supplies capacity, not permission. repeated HTTP/1 and HTTP/2 requests on
// the connection still check permission but spend only this one run-owned slot.
func (a *publicVisitorAdmission) commit() error {
	r := a.run
	r.mu.Lock()
	defer r.mu.Unlock()
	if !a.currentLocked() {
		return net.ErrClosed
	}
	if a.admittedLocked() {
		return nil
	}
	if r.draining || !time.Now().Before(a.expiresAt) || r.authorizedStreams >= r.streamCapacity {
		return &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
	}
	a.leavePendingLocked()
	a.phase = committedPublicSetup{}
	r.authorizedStreams++
	return nil
}

// the original setup deadline remains armed until stream-local promotion succeeds.
// a stable rejection can be returned again without replaying the decision, but
// cannot retain an idle connection beyond that deadline.
func (a *publicVisitorAdmission) completeSetup() error {
	a.run.mu.Lock()
	defer a.run.mu.Unlock()
	if _, committed := a.phase.(committedPublicSetup); !committed || !a.currentLocked() || !time.Now().Before(a.expiresAt) || !a.timer.Stop() {
		return net.ErrClosed
	}
	a.phase = promotedPublicSetup{}
	close(a.timerDone)
	return nil
}

func (a *publicVisitorAdmission) currentLocked() bool {
	if _, stopped := a.phase.(stoppedPublicSetup); stopped {
		return false
	}
	if _, retired := a.phase.(retiredPublicSetup); retired || a.run.closed || a.live.ctx.Err() != nil || a.run.sessions[a.live.ref.ConnectionSlot] != a.live {
		return false
	}
	select {
	case <-a.connection.closing:
		return false
	default:
		return true
	}
}

func (a *publicVisitorAdmission) stopPending() <-chan struct{} {
	r := a.run
	r.mu.Lock()
	if _, retired := a.phase.(retiredPublicSetup); retired {
		r.mu.Unlock()
		return a.done
	}
	if a.admittedLocked() {
		r.mu.Unlock()
		return nil
	}
	if _, stopped := a.phase.(stoppedPublicSetup); !stopped {
		a.phase = stoppedPublicSetup{previous: a.phase}
	}
	r.mu.Unlock()
	_ = a.connection.Close()
	return a.done
}

// retire runs after the visitor's HTTP handlers and promotion worker have joined.
// every close owner joins the same physical close before its permit is reusable.
func (a *publicVisitorAdmission) retire() {
	a.closeOnce.Do(func() {
		r := a.run
		r.mu.Lock()
		if _, stopped := a.phase.(stoppedPublicSetup); !stopped {
			a.phase = stoppedPublicSetup{previous: a.phase}
		}
		if a.timer.Stop() {
			close(a.timerDone)
		}
		r.mu.Unlock()
		_ = a.connection.Close()
		<-a.timerDone
		r.mu.Lock()
		delete(r.streams, a.stream)
		if a.admittedLocked() {
			r.authorizedStreams--
		} else {
			a.leavePendingLocked()
		}
		a.phase = retiredPublicSetup{}
		r.mu.Unlock()
		a.live.visitors.Done()
		r.handlers.Done()
		close(a.done)
	})
}
