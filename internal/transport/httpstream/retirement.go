package httpstream

import (
	"context"
	"net/http"
	"sync"
	"time"
)

type retirementKey struct{}

// RetireConnection stops admitting requests and gracefully closes this visitor
// connection after its responses finish, bounded by until. earlier requests keep
// their contexts until that bound or owner cancellation. repeated calls can only
// shorten the bound. zero means immediate retirement.
//
// r must come from ServeHandler (including Serve). a missing owner is a caller
// error; a response header is not a substitute for connection ownership.
func RetireConnection(w http.ResponseWriter, r *http.Request, until time.Time) {
	owner, ok := r.Context().Value(retirementKey{}).(*connectionRetirement)
	if !ok {
		panic("httpstream: connection retirement requires a serving owner")
	}
	if r.ProtoMajor == 1 {
		// publish HTTP/1's close before headers flush, even if the shutdown
		// worker has not yet disabled the server's keep-alives.
		w.Header().Set("Connection", "close")
	}
	owner.request(until)
}

type connectionRetirement struct {
	mu      sync.Mutex
	started chan struct{}
	changed chan struct{}
	set     bool
	until   time.Time
}

func newConnectionRetirement() *connectionRetirement {
	return &connectionRetirement{started: make(chan struct{}), changed: make(chan struct{}, 1)}
}

func (r *connectionRetirement) request(until time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.set && !until.Before(r.until) {
		return
	}
	r.until = until
	if !r.set {
		r.set = true
		close(r.started)
	}
	select {
	case r.changed <- struct{}{}:
	default:
	}
}

// watch applies both run drain and request-driven retirement to the same fence.
// it stays alive through handler and final-framing joins, including upgrades.
func (r *connectionRetirement) watch(ctx context.Context, drain Drain, expire func()) error {
	var timer *time.Timer
	var expired <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	started := drain.Started
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-started:
			started = nil
			r.request(drain.Deadline())
		case <-r.changed:
			r.mu.Lock()
			until := r.until
			r.mu.Unlock()
			if !time.Now().Before(until) {
				expire()
				return context.DeadlineExceeded
			}
			if timer == nil {
				timer = time.NewTimer(time.Until(until))
				expired = timer.C
			} else {
				timer.Reset(time.Until(until))
			}
		case <-expired:
			expire()
			return context.DeadlineExceeded
		}
	}
}
