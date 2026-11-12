package httpaccess

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
)

// one admitted request owns its guard, including after an HTTP/1 upgrade.
// cancellation and response-controller deadlines affect only that HTTP/2 stream;
// no guard closes the shared visitor TLS connection.
type Guard struct {
	http.ResponseWriter
	mu       sync.Mutex
	expired  bool
	finished bool
	upgraded net.Conn
	cancel   context.CancelFunc
	local    *visitorlease.Guard
	release  func()
}

func guardLocalHTTPRequest(w http.ResponseWriter, r *http.Request, policy *visitorlease.Lease, permission httpPermission) (*Guard, *http.Request, error) {
	ctx, cancel := context.WithCancel(r.Context())
	g := &Guard{ResponseWriter: w, cancel: cancel}
	guard, err := permission.bind(policy, g.abort)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	g.local = guard
	if err := ctx.Err(); err != nil {
		guard.Close()
		cancel()
		return nil, nil, err
	}
	clean := r.Clone(ctx)
	for key := range clean.Header {
		if strings.EqualFold(key, VisitorTokenHeader) || strings.EqualFold(key, ShareHeaderName) {
			delete(clean.Header, key)
		}
	}
	// publisher-owned feedback and sign-in handlers still need their fact
	// cookies. the HTTP forwarding boundary strips those before the app.
	return g, clean, nil
}

func (g *Guard) abort() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.abortLocked()
}

func (g *Guard) abortLocked() {
	if g.expired || g.finished {
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

func (g *Guard) Finish() {
	if g.local != nil {
		g.local.Close()
	}
	if g.release != nil {
		g.release()
	}
	g.cancel()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.finished = true
	if g.expired {
		// prevent a clean end-of-body after authorization ended. net/http sends
		// RST_STREAM for HTTP/2 and closes only this HTTP/1 connection.
		panic(http.ErrAbortHandler)
	}
}

func (g *Guard) Unwrap() http.ResponseWriter { return g.ResponseWriter }

func (g *Guard) FlushError() error {
	return http.NewResponseController(g.ResponseWriter).Flush()
}

func (g *Guard) Flush() { _ = g.FlushError() }

func (g *Guard) Hijack() (net.Conn, *bufio.ReadWriter, error) {
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
