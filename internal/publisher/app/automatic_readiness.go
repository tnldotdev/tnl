package app

import (
	"context"
	"time"
)

// startReadiness owns finite startup checks, not ongoing health monitoring. a
// detected target replacement cancels and joins its predecessor before getting
// a fresh bounded check. the idle event listener issues no application requests.
func (w *Workers) startReadiness(ctx context.Context, service Service, run uint64) func() {
	budget := w.readinessBudget
	if budget <= 0 {
		budget = 2 * time.Minute
	}
	delay := w.readinessDelay
	if delay == nil {
		delay = RetryDelay
	}
	ctx, cancel := context.WithCancel(ctx)
	changed, unwatch := w.Manager.watchTargetChanges(service.RegistrationID)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		defer unwatch()
		var stop context.CancelFunc
		var checked <-chan struct{}
		start := func() {
			call, end := context.WithTimeout(ctx, budget)
			finished := make(chan struct{})
			stop, checked = end, finished
			go func() {
				defer close(finished)
				defer end()
				w.checkReadiness(call, service, run, delay)
			}()
		}
		join := func() {
			if stop != nil {
				stop()
				<-checked
				stop, checked = nil, nil
			}
		}
		start()
		for {
			select {
			case <-ctx.Done():
				join()
				return
			case <-changed:
				join()
				// collapse identities detected while the old check was joining.
				select {
				case <-changed:
				default:
				}
				start()
			case <-checked:
				join()
			}
		}
	}()
	return func() { cancel(); <-done }
}

func (w *Workers) checkReadiness(ctx context.Context, service Service, run uint64, delay func(int) time.Duration) {
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
}
