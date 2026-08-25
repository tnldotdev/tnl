package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

func stopRoutes(ctx context.Context, processes []*routeProcess, parallel int, onFailure func()) (phaseResult, error) {
	started := time.Now().UTC()
	type outcome struct {
		duration time.Duration
		err      error
	}
	outcomes := make([]outcome, len(processes))
	concurrency := min(max(1, parallel), len(processes))
	var workers sync.WaitGroup
	var firstFailure sync.Once
	for worker := range concurrency {
		workers.Go(func() {
			for index := worker; index < len(processes); index += concurrency {
				process := processes[index]
				if process == nil {
					continue
				}
				began := time.Now()
				// Leave other routes running until a shutdown slot is available.
				process.cancel()
				err := ctx.Err()
				if err == nil {
					select {
					case err = <-process.done:
						if cancellationOnly(err) {
							err = nil
						}
					case <-ctx.Done():
						err = ctx.Err()
					}
				}
				outcomes[index] = outcome{duration: time.Since(began), err: err}
				if err != nil && onFailure != nil {
					firstFailure.Do(onFailure)
				}
			}
		})
	}
	workers.Wait()
	phase := phaseResult{Name: "deactivation", StartedAt: started, DurationMilliseconds: milliseconds(time.Since(started)), Concurrency: concurrency}
	var durations []time.Duration
	var stopErr error
	for index, process := range processes {
		if process == nil {
			continue
		}
		phase.Attempts++
		durations = append(durations, outcomes[index].duration)
		if err := outcomes[index].err; err != nil {
			phase.Errors++
			stopErr = errors.Join(stopErr, fmt.Errorf("stop route %d: %w", process.index, err))
		} else {
			phase.Successes++
		}
	}
	phase.Total = newDurationHistogram(durations)
	return phase, stopErr
}

// A joined cancellation and close failure is a failure, even though errors.Is
// also matches context.Canceled. Only pure cancellation is expected on stop.
func cancellationOnly(err error) bool {
	if err == nil || err == context.Canceled {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !cancellationOnly(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		if child := wrapped.Unwrap(); child != nil {
			return cancellationOnly(child)
		}
	}
	return false
}
