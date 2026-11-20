// Package workerloop schedules bounded background-work iterations. callers own
// work selection, error reporting, and any durable retry state.
package workerloop

import (
	"context"
	"errors"
	"time"
)

// Process performs one iteration and reports whether more work is immediately
// available. the caller owns any durable retry state.
type Process func(context.Context) (more bool, err error)

// Config describes scheduling and leaves failure reporting with the caller.
type Config struct {
	OperationTimeout time.Duration
	IdleInterval     time.Duration
	Process          Process
	OnError          func(error)
}

type lifetimeKey struct{}

// LifetimeEnded distinguishes process shutdown from an iteration's own deadline.
// outside Run, explicit cancellation remains ordinary caller control flow.
func LifetimeEnded(ctx context.Context) bool {
	if lifetime, ok := ctx.Value(lifetimeKey{}).(context.Context); ok {
		return lifetime.Err() != nil
	}
	return errors.Is(ctx.Err(), context.Canceled)
}

// Attempt gives one operation its own deadline without changing the context
// used to distinguish worker shutdown from an operation timeout.
func Attempt(ctx context.Context, timeout time.Duration, process Process) (bool, error) {
	operationCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return process(context.WithValue(operationCtx, lifetimeKey{}, ctx))
}

// Run starts immediately and repeats without waiting while an iteration finds
// more work and succeeds. empty or failed iterations wait for IdleInterval.
// each iteration has its own deadline; OnError decides how to report failures,
// including those returned during caller cancellation.
func Run(ctx context.Context, config Config) error {
	if config.OperationTimeout <= 0 || config.IdleInterval <= 0 || config.Process == nil {
		return errors.New("workerloop: positive operation timeout, idle interval, and process are required")
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
		// a ready timer and a canceled context can win the select in either
		// order. never start another iteration after observing cancellation.
		if ctx.Err() != nil {
			return nil
		}
		more, err := Attempt(ctx, config.OperationTimeout, config.Process)
		if err != nil && config.OnError != nil {
			config.OnError(err)
		}
		if ctx.Err() != nil {
			return nil
		}
		delay := time.Duration(0)
		if !more || err != nil {
			delay = config.IdleInterval
		}
		timer.Reset(delay)
	}
}
