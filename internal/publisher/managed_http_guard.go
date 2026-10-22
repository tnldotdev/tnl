package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"time"

	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// one guard covers idle keepalive, streaming bodies and upgraded connections.
// rotation changes only subsequent authorization; application bytes are never
// replayed. a failed recheck cannot extend the last successful deadline.
type managedHTTPGuard struct {
	frontend   ManagedHTTP
	client     *tls.Conn
	mu         sync.Mutex
	credential controlv1.ManagedHTTPCredential
	decision   controlv1.ServiceClientCertificateDecision
	revision   uint64
	wake       chan struct{}
	// authorize owns both the control mutation and the local decision update.
	// the state mutex remains independent so expiry can close stalled streams.
	authorization chan struct{}
}

func newManagedHTTPGuard(f ManagedHTTP, client *tls.Conn) *managedHTTPGuard {
	return &managedHTTPGuard{frontend: f, client: client, wake: make(chan struct{}, 1), authorization: make(chan struct{}, 1)}
}

func (g *managedHTTPGuard) lockAuthorization(ctx context.Context) error {
	select {
	case g.authorization <- struct{}{}:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (g *managedHTTPGuard) authorize(ctx context.Context, credential controlv1.ManagedHTTPCredential) (controlv1.ServiceClientCertificateDecision, error) {
	if err := g.lockAuthorization(ctx); err != nil {
		return controlv1.ServiceClientCertificateDecision{}, err
	}
	defer func() { <-g.authorization }()
	decision, err := g.frontend.authorize(ctx, credential)
	if err == nil && decision.Allowed && decision.Admitted && decision.ValidUntil.After(time.Now()) {
		g.update(credential, decision)
	}
	return decision, err
}

func (g *managedHTTPGuard) update(credential controlv1.ManagedHTTPCredential, decision controlv1.ServiceClientCertificateDecision) {
	g.mu.Lock()
	g.credential, g.decision = credential, decision
	g.revision++
	g.mu.Unlock()
	select {
	case g.wake <- struct{}{}:
	default:
	}
}

func (g *managedHTTPGuard) run(ctx context.Context) {
	defer g.client.Close()
	for {
		g.mu.Lock()
		credential, decision, revision := g.credential, g.decision, g.revision
		g.mu.Unlock()
		if revision == 0 {
			select {
			case <-ctx.Done():
				return
			case <-g.wake:
				continue
			}
		}
		remaining := time.Until(decision.ValidUntil)
		if remaining <= 0 {
			g.mu.Lock()
			current := revision == g.revision
			g.mu.Unlock()
			if !current {
				continue
			}
			return
		}
		// leave room for the bounded control request inside the 30-second
		// revocation interval, while never exceeding an earlier expiry.
		timer := time.NewTimer(max(time.Millisecond, min(25*time.Second, remaining/2)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-g.wake:
			timer.Stop()
			continue
		case <-timer.C:
		}
		check, cancel := context.WithDeadline(ctx, minTimeHTTP(decision.ValidUntil, time.Now().Add(5*time.Second)))
		// closing at the saved deadline also interrupts a stalled body or an
		// upgrade even when the authorization call is unavailable.
		expire := time.AfterFunc(max(0, time.Until(decision.ValidUntil)), func() {
			g.mu.Lock()
			current := revision == g.revision
			g.mu.Unlock()
			if current {
				_ = g.client.Close()
			}
		})
		// acquire before issuing the control request: discarding an old result
		// locally cannot undo its credential update in control's transaction.
		keep := g.recheck(check, credential, revision)
		cancel()
		expire.Stop()
		if !keep {
			return
		}
	}
}

func (g *managedHTTPGuard) recheck(ctx context.Context, credential controlv1.ManagedHTTPCredential, revision uint64) bool {
	if g.lockAuthorization(ctx) != nil {
		return true
	}
	defer func() { <-g.authorization }()
	g.mu.Lock()
	current := revision == g.revision
	g.mu.Unlock()
	if !current {
		return true
	}
	next, err := g.frontend.authorize(ctx, credential)
	g.mu.Lock()
	defer g.mu.Unlock()
	if revision != g.revision {
		return true
	}
	if err != nil {
		return errors.Is(err, controlclient.ErrUnavailable)
	}
	if !next.Allowed || !next.Admitted || !next.ValidUntil.After(time.Now()) {
		return false
	}
	g.decision = next
	return true
}

func minTimeHTTP(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
