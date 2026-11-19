package tunnel

import (
	"context"
	"errors"
	"sync"
	"time"
)

// AttemptResult keeps an authenticated value separate from operation and cleanup
// failures. role owners classify rejection and retain their own failure facts.
type AttemptResult[T any] struct {
	Value          T
	Accepted       bool
	Err            error
	CleanupErr     error
	Terminal       bool
	WaitForSibling bool
}

// RaceAttempts runs at most two authenticated attempts. it cancels and joins
// every started attempt and closes every unselected success before returning.
// callers install the winner only after checking all returned cleanup failures.
func RaceAttempts[T any](
	ctx context.Context,
	delay time.Duration,
	primary, fallback func(context.Context) AttemptResult[T],
	closeValue func(T) error,
) (winner AttemptResult[T], failures []AttemptResult[T], result error) {
	if delay < 0 || primary == nil || fallback == nil || closeValue == nil {
		return winner, nil, errors.New("tunnel: two attempts, cleanup and a non-negative delay are required")
	}
	if cause := context.Cause(ctx); cause != nil {
		return winner, nil, cause
	}
	race, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan AttemptResult[T], 2)
	var workers sync.WaitGroup
	defer workers.Wait()
	start := func(attempt func(context.Context) AttemptResult[T]) {
		workers.Go(func() { results <- attempt(race) })
	}
	start(primary)
	remaining, fallbackStarted := 1, false
	timer := time.NewTimer(delay)
	defer timer.Stop()
	stopped := ctx.Done()
	var siblingFailure error
	for remaining > 0 {
		select {
		case <-stopped:
			stopped = nil
			result = context.Cause(ctx)
			cancel()
		case <-timer.C:
			if !fallbackStarted && !winner.Accepted && result == nil {
				fallbackStarted = true
				remaining++
				start(fallback)
			}
		case next := <-results:
			remaining--
			if next.Accepted {
				if !winner.Accepted && result == nil && ctx.Err() == nil {
					winner = next
					cancel()
				} else {
					next.CleanupErr = errors.Join(next.CleanupErr, closeValue(next.Value))
					failures = append(failures, next)
				}
				continue
			}
			failures = append(failures, next)
			if next.Terminal && result == nil && !winner.Accepted {
				if next.WaitForSibling && remaining > 0 {
					siblingFailure = next.Err
				} else {
					result = next.Err
					cancel()
				}
			}
			if !fallbackStarted && !winner.Accepted && result == nil && ctx.Err() == nil {
				fallbackStarted = true
				remaining++
				start(fallback)
			}
		}
	}
	if cause := context.Cause(ctx); cause != nil {
		result = errors.Join(result, cause)
	}
	if !winner.Accepted && result == nil {
		result = siblingFailure
		if result == nil {
			for _, failure := range failures {
				result = errors.Join(result, failure.Err)
			}
		}
	}
	return winner, failures, result
}
