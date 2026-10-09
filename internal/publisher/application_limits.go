package publisher

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/localproxy"
)

// ApplicationLimits bounds application requests after visitor access is resolved.
// zero requests and rate mean no cap; zero concurrency selects the default.
type ApplicationLimits struct {
	Requests     int
	RateRequests int
	RatePer      time.Duration
	Concurrency  int
}

func (limits ApplicationLimits) validate() error {
	if limits.Requests < 0 || limits.Concurrency < 0 || limits.RateRequests < 0 || limits.RatePer < 0 ||
		(limits.RateRequests == 0) != (limits.RatePer == 0) {
		return errors.New("publisher: application limits must be positive and rate requires both requests and period")
	}
	return nil
}

type applicationAdmission struct {
	mu        sync.Mutex
	limits    ApplicationLimits
	used      int
	active    int
	tokens    float64
	updatedAt time.Time
	completed chan struct{}
}

func newApplicationAdmission(limits ApplicationLimits) (*applicationAdmission, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if limits.Concurrency == 0 {
		limits.Concurrency = localproxy.DefaultRequestLimit
	}
	return &applicationAdmission{limits: limits, tokens: float64(limits.RateRequests), completed: make(chan struct{})}, nil
}

// enter returns a status and retry delay on rejection, or zero on admission.
func (a *applicationAdmission) enter(now time.Time) (int, time.Duration) {
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
			a.tokens = min(float64(a.limits.RateRequests), a.tokens+elapsed*float64(a.limits.RateRequests)/a.limits.RatePer.Seconds())
		}
		a.updatedAt = now
		if a.tokens < 1 {
			remaining := (1 - a.tokens) * a.limits.RatePer.Seconds() / float64(a.limits.RateRequests)
			return http.StatusTooManyRequests, max(time.Duration(remaining*float64(time.Second)), time.Second)
		}
		a.tokens--
	}
	a.used++
	a.active++
	return 0, 0
}

func (a *applicationAdmission) leave() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.active--
	if a.limits.Requests > 0 && a.used == a.limits.Requests && a.active == 0 {
		close(a.completed)
	}
}
