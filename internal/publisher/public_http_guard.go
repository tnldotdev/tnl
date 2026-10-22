package publisher

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// one admitted request owns its guard, including after an HTTP/1 upgrade.
// cancellation and response-controller deadlines affect only that HTTP/2 stream;
// no guard closes the shared visitor TLS connection.
type publicHTTPGuard struct {
	http.ResponseWriter
	mu       sync.Mutex
	until    time.Time
	expired  bool
	finished bool
	upgraded net.Conn
	cancel   context.CancelFunc
	timer    *time.Timer
	done     chan struct{}
}

func guardPublicHTTPRequest(w http.ResponseWriter, r, authorization *http.Request, access *browserAccess, initial controlv1.HTTPVisitorResponse, checkedAt time.Time) (*publicHTTPGuard, *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	g := &publicHTTPGuard{ResponseWriter: w, until: *initial.ValidUntil, cancel: cancel, done: make(chan struct{})}
	// retain the original credential and trusted visitor/run. application header
	// stripping or a later browser sign-in cannot replace an admitted subject.
	original := authorization.Clone(ctx)
	bound := *access
	g.timer = time.AfterFunc(max(0, time.Until(g.until)), g.expire)
	go func() {
		defer close(g.done)
		g.run(ctx, original, &bound, initial, checkedAt)
	}()
	return g, r.WithContext(ctx)
}

func (g *publicHTTPGuard) run(ctx context.Context, original *http.Request, access *browserAccess, initial controlv1.HTTPVisitorResponse, checkedAt time.Time) {
	until := *initial.ValidUntil
	// admission from the cache keeps the age of its last successful check.
	// starting another request must not restart the revocation interval.
	nextCheck := checkedAt.Add(visitorDecisionRecheck)
	for {
		timer := time.NewTimer(max(time.Millisecond, min(time.Until(nextCheck), time.Until(until)/2)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		check, cancel := context.WithDeadline(ctx, earlierDecisionTime(until, time.Now().Add(5*time.Second)))
		next, nextCheckedAt, err := access.currentDecision(original.WithContext(check), true)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, controlclient.ErrUnavailable) {
			nextCheck = time.Now().Add(visitorDecisionRetry)
			continue
		}
		if err != nil || !next.VisitAllowed || next.ValidUntil == nil || !next.ValidUntil.After(time.Now()) || !sameHTTPVisitor(initial, next) {
			g.abort()
			return
		}
		g.mu.Lock()
		if g.expired || !g.until.After(time.Now()) {
			g.mu.Unlock()
			g.abort()
			return
		}
		until, g.until = *next.ValidUntil, *next.ValidUntil
		g.timer.Reset(max(0, time.Until(until)))
		g.mu.Unlock()
		nextCheck = nextCheckedAt.Add(visitorDecisionRecheck)
		if !nextCheckedAt.After(checkedAt) {
			nextCheck = time.Now().Add(visitorDecisionRetry)
		}
		checkedAt = nextCheckedAt
	}
}

func sameHTTPVisitor(a, b controlv1.HTTPVisitorResponse) bool {
	if a.IdentityId == nil || b.IdentityId == nil {
		return a.IdentityId == nil && b.IdentityId == nil
	}
	return *a.IdentityId == *b.IdentityId
}

func (g *publicHTTPGuard) expire() {
	g.mu.Lock()
	defer g.mu.Unlock()
	// a timer already firing before renewal must check the current deadline.
	if !g.finished && !g.until.After(time.Now()) {
		g.abortLocked()
	}
}

func (g *publicHTTPGuard) abort() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.abortLocked()
}

func (g *publicHTTPGuard) abortLocked() {
	if g.expired {
		return
	}
	g.expired = true
	g.cancel()
	// net/http implements these deadlines per stream for HTTP/2. cancellation
	// also interrupts the target request, including a stalled response body.
	controller := http.NewResponseController(g.ResponseWriter)
	_ = controller.SetReadDeadline(time.Now())
	_ = controller.SetWriteDeadline(time.Now())
	if g.upgraded != nil {
		_ = g.upgraded.Close()
	}
}

func (g *publicHTTPGuard) finish() {
	g.cancel()
	<-g.done
	g.mu.Lock()
	defer g.mu.Unlock()
	g.timer.Stop()
	g.finished = true
	if g.expired {
		// prevent a clean end-of-body after authorization ended. net/http sends
		// RST_STREAM for HTTP/2 and closes only this HTTP/1 connection.
		panic(http.ErrAbortHandler)
	}
}

func (g *publicHTTPGuard) Unwrap() http.ResponseWriter { return g.ResponseWriter }

func (g *publicHTTPGuard) FlushError() error {
	return http.NewResponseController(g.ResponseWriter).Flush()
}

func (g *publicHTTPGuard) Flush() { _ = g.FlushError() }

func (g *publicHTTPGuard) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(g.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	g.mu.Lock()
	g.upgraded = conn
	if g.expired {
		_ = conn.Close()
	}
	g.mu.Unlock()
	return conn, rw, nil
}
