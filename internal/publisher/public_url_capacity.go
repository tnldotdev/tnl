package publisher

import (
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// publicVisitorAdmission belongs to one accepted stream, not its HTTP requests.
// the live session supplies the trusted domain; opening headers cannot select it.
type publicVisitorAdmission struct {
	run          *PublicURLServer
	live         *livePublisherSession
	stream       net.Conn
	connection   *doneConn
	reservation  *visitorlease.ReservationGuard
	mu           sync.Mutex
	admitted     bool
	released     bool
	timer        *time.Timer
	timerDone    chan struct{}
	timerStopped bool
	expiresAt    time.Time
	done         chan struct{}
	stopped      bool
}

func (r *PublicURLServer) reservePublicSetup(live *livePublisherSession, stream net.Conn) (*publicVisitorAdmission, tunnelv1.ErrorCode) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.draining || live == nil || live.ctx.Err() != nil || r.sessions[live.ref.ConnectionSlot] != live {
		return nil, tunnelv1.Unavailable
	}
	domain := live.ref.RelayServiceID
	if r.pendingStreams >= 2*PendingSetupsPerRelay || r.pendingRelays[domain] >= PendingSetupsPerRelay {
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
	a.timer = time.AfterFunc(visitorPromotionTimeout, func() { defer close(a.timerDone); _ = a.connection.Close() })
	return a, ""
}

func (a *publicVisitorAdmission) currentLocked() bool {
	r := a.run
	return !r.closed && a.live.ctx.Err() == nil && r.sessions[a.live.ref.ConnectionSlot] == a.live
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

func (a *publicVisitorAdmission) commit(permission *visitorlease.Guard) error {
	a.mu.Lock()
	closeStream := false
	defer func() {
		a.mu.Unlock()
		if closeStream {
			_ = a.connection.Close()
		}
	}()
	r := a.run
	r.mu.Lock()
	if a.released || a.stopped || !a.currentLocked() || !a.admitted && (!time.Now().Before(a.expiresAt) || r.authorizedStreams >= r.streamCapacity) {
		r.mu.Unlock()
		return &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
	}
	if !a.admitted {
		r.authorizedStreams++
	}
	r.mu.Unlock()
	// reserve tentatively, then check current permission and the exact claim
	// without nesting the run mutex with the lease or invoking network work.
	err := a.reservation.Commit(permission)
	r.mu.Lock()
	if err != nil || !a.currentLocked() {
		if !a.admitted {
			r.authorizedStreams--
		}
		r.mu.Unlock()
		if err != nil {
			return err
		}
		a.reservation.Close()
		closeStream = true
		return net.ErrClosed
	}
	if !a.admitted {
		a.timerStopped = a.timer.Stop()
		if !a.timerStopped || !time.Now().Before(a.expiresAt) {
			r.authorizedStreams--
			r.mu.Unlock()
			a.reservation.Close()
			closeStream = true
			return net.ErrClosed
		}
		a.leavePendingLocked()
		a.admitted = true
	}
	r.mu.Unlock()
	return nil
}

// stopPending races permission commit under the stream mutex. an admitted
// visitor is never selected from an earlier, unlocked drain snapshot.
func (a *publicVisitorAdmission) stopPending() <-chan struct{} {
	a.mu.Lock()
	if a.admitted {
		a.mu.Unlock()
		return nil
	}
	if a.released {
		a.mu.Unlock()
		return a.done
	}
	a.stopped = true
	a.mu.Unlock()
	_ = a.connection.Close()
	return a.done
}

func (a *publicVisitorAdmission) close() {
	a.mu.Lock()
	if a.released {
		a.mu.Unlock()
		<-a.done
		return
	}
	a.released = true
	timerStopped := a.timerStopped || a.timer.Stop()
	a.mu.Unlock()
	if !timerStopped {
		<-a.timerDone
	}
	if a.reservation != nil {
		a.reservation.Close()
	}
	r := a.run
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
}
