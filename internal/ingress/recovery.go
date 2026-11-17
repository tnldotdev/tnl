package ingress

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

type recoveryControl interface {
	ObserveRecovery(context.Context, ingressv1.ServiceRunReference, string, uint64, time.Time, []byte) (ingressv1.ServiceRecoveryObservation, error)
}

type RecoveryObserver interface {
	AddRecoveryPending(int)
	ObserveRecoveryAttempt(observability.RecoveryAttemptOutcome)
}

// RecoveryReporter retries first-public-byte observations until control
// durably completes the corresponding recovery episode.
type RecoveryReporter struct {
	ctx     context.Context
	cancel  context.CancelFunc
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
	ctx, cancel := context.WithCancel(ctx)
	return &RecoveryReporter{
		ctx: ctx, cancel: cancel, control: control, retry: retry, report: report, pending: make(map[uint64]struct{}),
	}, nil
}

func (r *RecoveryReporter) Observe(run ingressv1.ServiceRunReference, visitor string, recoveryEpisodeID uint64, observedAt time.Time, sourceEvidence []byte) {
	if r == nil || r.control == nil || recoveryEpisodeID == 0 || len(sourceEvidence) > 2048 {
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
	sourceEvidence = bytes.Clone(sourceEvidence)
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
			if _, err := r.control.ObserveRecovery(r.ctx, run, visitor, recoveryEpisodeID, observedAt, sourceEvidence); err == nil {
				if r.observer != nil {
					r.observer.ObserveRecoveryAttempt("success")
				}
				return
			} else {
				var problem *ControlProblemError
				if errors.As(err, &problem) && problem.Status == http.StatusConflict && problem.Problem != nil &&
					(problem.Problem.Code == ingressv1.RecoveryEpisodeStale || problem.Problem.Code == ingressv1.IngressLeaseStale) {
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
		r.cancel()
		return nil
	case <-ctx.Done():
		r.cancel()
		<-done
		return context.Cause(ctx)
	}
}
