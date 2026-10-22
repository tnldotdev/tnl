package projectpublisher

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
)

// startReadiness owns one run's retry budget, including delays and in-flight
// probes. its stop function cancels and joins before drain or a replacement run.
func (w *Workers) startReadiness(ctx context.Context, service clientruntime.Service, run uint64) func() {
	budget := w.readinessBudget
	if budget <= 0 {
		budget = 2 * time.Minute
	}
	delay := w.readinessDelay
	if delay == nil {
		delay = clientruntime.RetryDelay
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		for attempt := 0; ; attempt++ {
			if ctx.Err() != nil {
				return
			}
			if attempt > 0 {
				timer := time.NewTimer(delay(attempt - 1))
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
			if ctx.Err() != nil {
				return
			}
			current, ok := w.Manager.ServiceForRun(service.Name, service.RegistrationID, service.Target, run)
			if !ok || !current.Routable || current.Ready {
				return
			}
			if w.checkService(ctx, current) {
				return
			}
		}
	}()
	return func() { cancel(); <-done }
}
