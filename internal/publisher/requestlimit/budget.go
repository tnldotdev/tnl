package requestlimit

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// HTTP shares one run's application budget across all
// visitor connections. private and public HTTP use the same admission counter.
type HTTP struct{ admission *Budget }

func NewHTTP(input *controlv1.ProjectHTTPApplicationLimits) (*HTTP, error) {
	var limits applicationlimits.Limits
	if input != nil {
		if input.Total != nil {
			limits.Requests = *input.Total
		}
		if input.Concurrency != nil {
			limits.Concurrency = *input.Concurrency
		}
		if input.Rate != nil {
			period, err := time.ParseDuration(input.Rate.Per)
			if err != nil {
				return nil, err
			}
			limits.RateRequests, limits.RatePer = input.Rate.Count, period
			if input.Rate.Burst != nil {
				limits.RateBurst = *input.Rate.Burst
			}
		}
	}
	admission, err := New(limits)
	if err != nil {
		return nil, err
	}
	return &HTTP{admission: admission}, nil
}

// admit holds one run-wide request slot until the returned release is called.
func (l *HTTP) Admit(w http.ResponseWriter, r *http.Request) (func(), bool) {
	if l == nil {
		return func() {}, true
	}
	release, status, retry := l.admission.Acquire(r.Context())
	if status != 0 {
		if retry > 0 {
			w.Header().Set("Retry-After", fmt.Sprint(RetryAfterSeconds(retry)))
		}
		w.Header().Set("Connection", "close")
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second))
		http.Error(w, "HTTP request limit reached", status)
		return nil, false
	}
	return release, true
}

// Budget owns admission for one run, not one visitor connection.
type Budget struct {
	mu        sync.Mutex
	limits    applicationlimits.Limits
	used      int
	active    int
	tokens    float64
	updatedAt time.Time
	completed chan struct{}
}

func New(limits applicationlimits.Limits) (*Budget, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	limits = limits.Defaults(false)
	return &Budget{limits: limits, tokens: float64(limits.RateBurst), completed: make(chan struct{})}, nil
}

func (a *Budget) Limits() applicationlimits.Limits { return a.limits }
func (a *Budget) Completed() <-chan struct{}       { return a.completed }

// acquire has no wait queue. cancellation cannot leave a held concurrency slot.
// release is idempotent so cancellation and normal cleanup may race safely.
func (a *Budget) Acquire(ctx context.Context) (func(), int, time.Duration) {
	if ctx.Err() != nil {
		return nil, http.StatusServiceUnavailable, time.Second
	}
	status, retry := a.enter(time.Now())
	if status != 0 {
		return nil, status, retry
	}
	var once sync.Once
	release := func() { once.Do(a.leave) }
	if ctx.Err() != nil {
		a.Refund()
		return nil, http.StatusServiceUnavailable, time.Second
	}
	return release, 0, 0
}

// refund is used only before application forwarding, when promotion fails or
// setup is canceled. it restores all three budgets, including the rate token.
func (a *Budget) Refund() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.limits.Requests > 0 {
		a.used--
	}
	a.active--
	a.tokens = min(float64(a.limits.RateBurst), a.tokens+1)
}

// enter checks all limits under one lock. the lifetime request budget counts
// admitted requests and never refills; active requests hold a concurrency slot
// until leave. the token bucket starts full, refills by elapsed time at the
// configured requests-per-period rate, and cannot exceed the configured burst.
// rejection spends no request budget or token. rate rejection returns the time
// until another token is available, rounded up to at least one second.
func (a *Budget) enter(now time.Time) (int, time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.limits.Requests > 0 && a.used >= a.limits.Requests {
		return http.StatusServiceUnavailable, 0
	}
	if a.active >= a.limits.Concurrency {
		return http.StatusServiceUnavailable, time.Second
	}
	if a.limits.RateRequests > 0 {
		if !a.updatedAt.IsZero() && now.After(a.updatedAt) {
			elapsed := now.Sub(a.updatedAt).Seconds()
			a.tokens = min(float64(a.limits.RateBurst), a.tokens+elapsed*float64(a.limits.RateRequests)/a.limits.RatePer.Seconds())
		}
		if now.After(a.updatedAt) {
			a.updatedAt = now
		}
		if a.tokens < 1 {
			nanos := math.Ceil((1 - a.tokens) * float64(a.limits.RatePer) / float64(a.limits.RateRequests))
			retry := time.Duration(math.MaxInt64)
			if nanos < float64(math.MaxInt64) {
				retry = time.Duration(nanos)
			}
			return http.StatusTooManyRequests, max(retry, time.Second)
		}
		a.tokens--
	}
	if a.limits.Requests > 0 {
		a.used++
	}
	a.active++
	return 0, 0
}

func RetryAfterSeconds(retry time.Duration) int64 {
	seconds := int64(retry / time.Second)
	if retry%time.Second != 0 {
		seconds++
	}
	return max(seconds, 1)
}

// leave frees a concurrency slot and signals completion after the final
// admitted request finishes when the lifetime budget is spent.
func (a *Budget) leave() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.active--
	if a.limits.Requests > 0 && a.used == a.limits.Requests && a.active == 0 {
		close(a.completed)
	}
}
