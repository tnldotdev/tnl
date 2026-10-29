package publisher

import (
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// pending setups are bounded per trusted relay service,
// independently of the run's authorized visitor connections.
const PendingSetupsPerRelay = 4

// publicVisitorAdmission belongs to a connection, not an HTTP request. the run
// owns all counters, including retiring sessions from the same relay service.
type publicVisitorAdmission struct {
	run        *PublicURLServer
	live       *livePublisherSession
	stream     net.Conn
	connection *doneConn
	admitted   bool // protected by run.mu
	stopped    bool // protected by run.mu
	timer      *time.Timer
	timerDone  chan struct{}
	expiresAt  time.Time
	closeOnce  sync.Once
	done       chan struct{}
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
	a := &publicVisitorAdmission{run: r, live: live, stream: stream, connection: newDoneConn(stream), timerDone: make(chan struct{}), done: make(chan struct{}), expiresAt: time.Now().Add(visitorPromotionTimeout)}
	r.streams[stream] = a
	a.timer = time.AfterFunc(visitorPromotionTimeout, func() {
		defer close(a.timerDone)
		_ = a.connection.Close()
	})
	return a, ""
}

func (a *publicVisitorAdmission) leavePendingLocked() {
	r := a.run
	domain := a.live.ref.RelayServiceID
	r.pendingStreams--
	r.pendingRelays[domain]--
	if r.pendingRelays[domain] == 0 {
		delete(r.pendingRelays, domain)
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
	if a.admitted {
		return nil
	}
	if r.draining || !time.Now().Before(a.expiresAt) || r.authorizedStreams >= r.streamCapacity {
		return &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
	}
	a.leavePendingLocked()
	a.admitted = true
	r.authorizedStreams++
	return nil
}

// the original setup deadline remains armed until sideband promotion succeeds.
// a stable rejection can be returned again without replaying the decision, but
// cannot retain an idle connection beyond that deadline.
func (a *publicVisitorAdmission) completeSetup() error {
	a.run.mu.Lock()
	defer a.run.mu.Unlock()
	if !a.currentLocked() || !time.Now().Before(a.expiresAt) || !a.timer.Stop() {
		return net.ErrClosed
	}
	close(a.timerDone)
	return nil
}

func (a *publicVisitorAdmission) currentLocked() bool {
	if a.stopped || a.run.closed || a.live.ctx.Err() != nil || a.run.sessions[a.live.ref.ConnectionSlot] != a.live {
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
	if a.admitted {
		r.mu.Unlock()
		return nil
	}
	a.stopped = true
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
		a.stopped = true
		if a.timer.Stop() {
			close(a.timerDone)
		}
		r.mu.Unlock()
		_ = a.connection.Close()
		<-a.timerDone
		r.mu.Lock()
		delete(r.streams, a.stream)
		if a.admitted {
			r.authorizedStreams--
		} else {
			a.leavePendingLocked()
		}
		r.mu.Unlock()
		a.live.visitors.Done()
		r.handlers.Done()
		close(a.done)
	})
}
