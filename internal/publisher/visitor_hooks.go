package publisher

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
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

type visitorPromotionPhase interface{ visitorPromotionPhase() }
type runningVisitorPromotion struct{ work *visitorPromotion }
type completedVisitorPromotion struct{ work *visitorPromotion }

func (runningVisitorPromotion) visitorPromotionPhase()   {}
func (completedVisitorPromotion) visitorPromotionPhase() {}

type visitorSessionPhase uint8

const (
	visitorSessionServing visitorSessionPhase = iota
	visitorSessionClosed
)

type visitorSession struct {
	visitor   Visitor
	promote   PromoteVisitor
	guard     AdmitVisitor
	life      context.Context
	cancel    context.CancelFunc
	capacity  *publicVisitorAdmission
	mu        sync.Mutex
	promotion visitorPromotionPhase // nil until the first admitted request
	phase     visitorSessionPhase
	workers   sync.WaitGroup
	requests  sync.WaitGroup
}

func (v *visitorSession) admit(ctx context.Context, readiness bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	v.mu.Lock()
	closed := v.phase == visitorSessionClosed
	v.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if v.life != nil && v.life.Err() != nil {
		return v.life.Err()
	}
	visitor := v.visitor
	visitor.Readiness = readiness
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
	if v.phase == visitorSessionClosed {
		v.mu.Unlock()
		return net.ErrClosed
	}
	if v.promotion == nil {
		work := &visitorPromotion{done: make(chan struct{})}
		v.promotion = runningVisitorPromotion{work: work}
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
			v.mu.Lock()
			v.promotion = completedVisitorPromotion{work: work}
			v.mu.Unlock()
			close(work.done)
		})
	}
	var work *visitorPromotion
	switch state := v.promotion.(type) {
	case runningVisitorPromotion:
		work = state.work
	case completedVisitorPromotion:
		work = state.work
	}
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
	if v.phase == visitorSessionClosed {
		return false
	}
	v.requests.Add(1)
	return true
}

func (v *visitorSession) close() {
	v.mu.Lock()
	v.phase = visitorSessionClosed
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
