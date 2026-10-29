package publisher

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// Visitor identifies one authenticated relay stream and its original endpoints.
// Header is absent only for in-process test connections. it is never derived
// from HTTP headers or database startup fields.
type Visitor struct {
	Run         PublishRunIdentity
	Header      tunnelv1.VisitorStreamHeader
	Source      netip.AddrPort
	Destination netip.AddrPort
	// readiness is set only after an exact, single-use proof was consumed.
	Readiness bool
}

// PromoteVisitor overrides ingress application promotion. the engine supplies
// the stream-local default. readiness never invokes this callback.
type PromoteVisitor func(context.Context, Visitor) error

// AdmitVisitor checks current application ownership on every use, including
// proven readiness GETs. unlike promotion, a successful check is not cached.
type AdmitVisitor func(context.Context, Visitor) error

const visitorPromotionTimeout = 10 * time.Second

type visitorPromotion struct {
	done chan struct{}
	err  error
}

type visitorSession struct {
	visitor   Visitor
	promote   PromoteVisitor
	guard     AdmitVisitor
	life      context.Context
	cancel    context.CancelFunc
	capacity  *publicVisitorAdmission
	mu        sync.Mutex
	promotion *visitorPromotion
	closed    bool
	workers   sync.WaitGroup
	requests  sync.WaitGroup
}

func (v *visitorSession) admit(ctx context.Context, readiness ...bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	v.mu.Lock()
	closed := v.closed
	v.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if v.life != nil && v.life.Err() != nil {
		return v.life.Err()
	}
	visitor := v.visitor
	visitor.Readiness = len(readiness) > 0 && readiness[0]
	if v.guard != nil {
		check, finish := observability.PublisherOperation(ctx, "visitor_authorization")
		err := v.guard(check, visitor)
		observability.PublisherAuthorization(check, err == nil, err == nil, err)
		finish(err)
		if err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.life != nil && v.life.Err() != nil {
		return v.life.Err()
	}
	// a proof authorizes this GET only. it neither spends application capacity
	// nor creates an ingress decision that a later request could reuse.
	if visitor.Readiness {
		return nil
	}
	if err := v.capacity.commit(); err != nil {
		return err
	}
	v.mu.Lock()
	if v.closed {
		v.mu.Unlock()
		return net.ErrClosed
	}
	if v.promotion == nil {
		work := &visitorPromotion{done: make(chan struct{})}
		v.promotion = work
		base := v.life
		if base == nil {
			base = context.Background()
		}
		v.workers.Go(func() {
			workCtx, cancel := context.WithTimeout(base, visitorPromotionTimeout)
			defer cancel()
			if v.promote != nil {
				var finish func(error)
				workCtx, finish = observability.PublisherOperation(workCtx, "visitor_authorization")
				work.err = v.promote(workCtx, visitor)
				observability.PublisherAuthorization(workCtx, work.err == nil, work.err == nil, work.err)
				finish(work.err)
			}
			if work.err == nil {
				work.err = workCtx.Err()
			}
			if work.err == nil {
				work.err = v.capacity.completeSetup()
			}
			if work.err == nil {
				// net/http owns request-body read deadlines. clear only the setup
				// write deadline so incomplete bodies retain their bounded lifetime.
				_ = v.capacity.connection.SetWriteDeadline(time.Time{})
			}
			// one shared decision is never replayed on an ambiguous transport
			// failure. request cancellation affects only its own waiter.
			close(work.done)
		})
	}
	work := v.promotion
	v.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-work.done:
		if err := ctx.Err(); err != nil {
			return err
		}
		if v.life != nil && v.life.Err() != nil {
			return v.life.Err()
		}
		return work.err
	}
}

func (v *visitorSession) beginRequest() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return false
	}
	v.requests.Add(1)
	return true
}

func (v *visitorSession) close() {
	v.mu.Lock()
	v.closed = true
	if v.cancel != nil {
		v.cancel()
	}
	v.mu.Unlock()
	v.workers.Wait()
	v.requests.Wait()
}

type livePublisherSession struct {
	session  *tunnel.Session
	ref      tunnelv1.PublisherConnectionRef
	ctx      context.Context
	cancel   context.CancelFunc
	visitors sync.WaitGroup
}

type visitorSessionKey struct{}

// ReadinessProof is a short-lived, single-use proof for one exact run and GET
// path. it stays in memory and is removed before target forwarding.
type ReadinessProof struct {
	mu      sync.Mutex
	run     PublishRunIdentity
	path    string
	secret  string
	expires time.Time
}

func NewReadinessProof(run PublishRunIdentity, path string) (*ReadinessProof, error) {
	if run.PublicURLID == "" || run.Number == 0 || run.Hostname == "" || !strings.HasPrefix(path, "/") ||
		strings.ContainsAny(path, "?#\r\n") || strings.HasPrefix(path, "/__tnl/") {
		return nil, errors.New("publisher: readiness proof requires an exact run and absolute path")
	}
	p := &ReadinessProof{run: run, path: path}
	if _, err := p.Renew(); err != nil {
		return nil, err
	}
	return p, nil
}

// Renew replaces any outstanding proof for a later check of the same run/path.
// the returned value belongs only in the probe's private request header.
func (p *ReadinessProof) Renew() (string, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.secret = hex.EncodeToString(secret[:])
	p.expires = time.Now().Add(2 * time.Minute)
	return p.secret, nil
}

func (p *ReadinessProof) HeaderValue() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.secret
}

func (p *ReadinessProof) consume(r *http.Request, run PublishRunIdentity) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	values := r.Header.Values(publisherproxy.ReadinessProbeHeader)
	if p.secret == "" || time.Now().After(p.expires) || run != p.run || r.Method != http.MethodGet ||
		r.URL.EscapedPath() != p.path || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.Header.Get("Upgrade") != "" || len(values) != 1 ||
		subtle.ConstantTimeCompare([]byte(values[0]), []byte(p.secret)) != 1 {
		return false
	}
	p.secret = ""
	return true
}
