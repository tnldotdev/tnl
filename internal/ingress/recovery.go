package ingress

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/problemtype"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

type recoveryControl interface {
	ObserveRecovery(context.Context, string, uint64, uint64, time.Time) (ingressv1.PublicURLRecoveryObservation, error)
}

type RecoveryObserver interface {
	AddRecoveryPending(int)
	ObserveRecoveryAttempt(observability.RecoveryAttemptOutcome)
}

// RecoveryReporter retries first-public-byte observations until control
// durably completes the corresponding recovery episode.
type RecoveryReporter struct {
	ctx     context.Context
	control recoveryControl
	retry   time.Duration
	report  func(error)

	mu       sync.Mutex
	pending  map[uint64]struct{}
	closed   bool
	active   sync.WaitGroup
	observer RecoveryObserver
}

// SetObserver configures process-local metrics before observations begin.
func (r *RecoveryReporter) SetObserver(observer RecoveryObserver) { r.observer = observer }

func NewRecoveryReporter(
	ctx context.Context,
	control recoveryControl,
	retry time.Duration,
	report func(error),
) (*RecoveryReporter, error) {
	if retry < 0 {
		return nil, errors.New("ingress: recovery retry interval cannot be negative")
	}
	if retry == 0 {
		retry = time.Second
	}
	if report == nil {
		report = func(error) {}
	}
	return &RecoveryReporter{
		ctx: ctx, control: control, retry: retry, report: report, pending: make(map[uint64]struct{}),
	}, nil
}

func (r *RecoveryReporter) Observe(publicURLID string, publishRunNumber, recoveryEpisodeID uint64, observedAt time.Time) {
	if r == nil || r.control == nil || recoveryEpisodeID == 0 {
		return
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	if _, exists := r.pending[recoveryEpisodeID]; exists {
		r.mu.Unlock()
		return
	}
	r.pending[recoveryEpisodeID] = struct{}{}
	if r.observer != nil {
		r.observer.AddRecoveryPending(1)
	}
	r.active.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.active.Done()
		defer func() {
			r.mu.Lock()
			delete(r.pending, recoveryEpisodeID)
			if r.observer != nil {
				r.observer.AddRecoveryPending(-1)
			}
			r.mu.Unlock()
		}()
		for {
			if _, err := r.control.ObserveRecovery(r.ctx, publicURLID, publishRunNumber, recoveryEpisodeID, observedAt); err == nil {
				if r.observer != nil {
					r.observer.ObserveRecoveryAttempt("success")
				}
				return
			} else {
				var problem *ControlProblemError
				if errors.As(err, &problem) && problem.Status == http.StatusConflict && problem.Problem != nil &&
					problemtype.Is(problem.Problem.Type, "recovery_episode_stale") {
					if r.observer != nil {
						r.observer.ObserveRecoveryAttempt("stale")
					}
					return
				}
				if r.observer != nil {
					outcome := observability.RecoveryAttemptRetry
					if r.ctx.Err() != nil {
						outcome = observability.RecoveryAttemptCanceled
					}
					r.observer.ObserveRecoveryAttempt(outcome)
				}
				if r.ctx.Err() == nil {
					r.report(err)
				}
			}
			timer := time.NewTimer(r.retry)
			select {
			case <-r.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
}

func (r *RecoveryReporter) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	done := make(chan struct{})
	go func() {
		r.active.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}
