package tnldruntime

import (
	"context"
	"errors"
	"io"
	"slices"
	"sync"
	"time"
)

// eventRecorder retains every observation, independently of how far any reader
// has advanced. notification is a broadcast, never a send to a consumer. no SUT
// callback waits for a reader, including readers that have already returned.
type eventRecorder[T any] struct {
	mu      sync.Mutex
	events  []T
	changed chan struct{}
	closed  bool
	err     error
}

func (r *eventRecorder[T]) notifyLocked() {
	if r.changed != nil {
		close(r.changed)
	}
	r.changed = make(chan struct{})
}

func (r *eventRecorder[T]) append(event T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	r.notifyLocked()
}

func (r *eventRecorder[T]) fail(err error) {
	if err == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// retain the first error; a noisy child must not grow an error tree forever.
	if r.err == nil {
		r.err = err
	}
	r.notifyLocked()
}

func (r *eventRecorder[T]) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.notifyLocked()
}

func (r *eventRecorder[T]) snapshot() ([]T, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.events), r.err
}

// each caller owns its cursor. a canceled wait does not consume an observation.
func (r *eventRecorder[T]) next(ctx context.Context, cursor *int) (T, error) {
	var zero T
	for {
		if err := ctx.Err(); err != nil {
			return zero, context.Cause(ctx)
		}
		r.mu.Lock()
		if r.err != nil {
			err := r.err
			r.mu.Unlock()
			return zero, err
		}
		if *cursor < len(r.events) {
			event := r.events[*cursor]
			*cursor += 1
			r.mu.Unlock()
			return event, nil
		}
		if r.closed {
			r.mu.Unlock()
			return zero, io.EOF
		}
		if r.changed == nil {
			r.changed = make(chan struct{})
		}
		changed := r.changed
		r.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return zero, context.Cause(ctx)
		}
	}
}

// pollCondition gives every blocking probe an operation deadline as well as the
// overall wait deadline. callbacks must use this context for queries/requests.
func pollCondition(ctx context.Context, interval, operationTimeout time.Duration, check func(context.Context) (bool, error)) error {
	var lastErr error
	for {
		if ctx.Err() != nil {
			return errors.Join(context.Cause(ctx), lastErr)
		}
		ready, err := func() (bool, error) {
			operation, cancel := context.WithTimeout(ctx, operationTimeout)
			defer cancel()
			return check(operation)
		}()
		if ready && ctx.Err() == nil {
			return nil
		}
		if err != nil {
			lastErr = err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(context.Cause(ctx), lastErr)
		case <-timer.C:
		}
	}
}
