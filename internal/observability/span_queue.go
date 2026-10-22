package observability

import (
	"context"
	"errors"
	"sync"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// spanQueue owns a bounded export queue without global SDK providers or feature
// flags. OnEnd never waits for the receiver. flush/drain share the caller bound.
type spanQueue struct {
	exporter sdktrace.SpanExporter
	state    *exportState
	queue    chan sdktrace.ReadOnlySpan
	commands chan queueCommand
	shutdown chan context.Context
	lifetime context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	mu       sync.RWMutex
	stopped  bool
	batch    int
	timeout  time.Duration
	result   error // published by closing done
}
type queueCommand struct {
	ctx    context.Context
	result chan error
}

func newSpanQueue(e sdktrace.SpanExporter, state *exportState, size, batch int, delay, timeout time.Duration) *spanQueue {
	lifetime, cancel := context.WithCancel(context.Background())
	q := &spanQueue{exporter: e, state: state, queue: make(chan sdktrace.ReadOnlySpan, size), commands: make(chan queueCommand, 1), shutdown: make(chan context.Context, 1), lifetime: lifetime, cancel: cancel, done: make(chan struct{}), batch: batch, timeout: timeout}
	go q.run(delay)
	return q
}
func (q *spanQueue) OnStart(context.Context, sdktrace.ReadWriteSpan) {}
func (q *spanQueue) OnEnd(span sdktrace.ReadOnlySpan) {
	if !span.SpanContext().IsSampled() {
		return
	}
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.stopped {
		return
	}
	select {
	case q.queue <- span:
	default:
		q.state.droppedSpans.Add(1)
	}
}
func (q *spanQueue) ForceFlush(ctx context.Context) error { return q.command(ctx) }
func (q *spanQueue) Shutdown(ctx context.Context) error {
	q.mu.Lock()
	previous := q.stopped
	q.stopped = true
	q.mu.Unlock()
	if previous {
		select {
		case <-q.done:
			return q.result
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	// the shutdown signal cannot be displaced by flush callers. its deadline also
	// cancels an export already in flight, so the worker cannot outlive that bound.
	if ctx.Err() != nil {
		q.cancel()
	}
	context.AfterFunc(ctx, q.cancel)
	q.shutdown <- ctx
	select {
	case <-q.done:
		return q.result
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (q *spanQueue) command(ctx context.Context) error {
	c := queueCommand{ctx: ctx, result: make(chan error, 1)}
	select {
	case q.commands <- c:
	case <-q.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-c.result:
		return err
	case <-q.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (q *spanQueue) run(delay time.Duration) {
	defer close(q.done)
	defer q.cancel()
	ticker := time.NewTicker(delay)
	defer ticker.Stop()
	batch := make([]sdktrace.ReadOnlySpan, 0, q.batch)
	export := func(ctx context.Context) error {
		if len(batch) == 0 {
			return nil
		}
		ctx, cancel := context.WithTimeout(ctx, q.timeout)
		defer cancel()
		stop := context.AfterFunc(q.lifetime, cancel)
		defer stop()
		err := ctx.Err()
		if err == nil {
			err = q.lifetime.Err()
		}
		if err == nil {
			err = q.exporter.ExportSpans(ctx, batch)
		}
		clear(batch)
		batch = batch[:0]
		return err
	}
	drain := func(ctx context.Context) error {
		var err error
		for remaining := len(q.queue); remaining > 0; remaining-- {
			batch = append(batch, <-q.queue)
			if len(batch) == q.batch {
				err = errors.Join(err, export(ctx))
			}
		}
		err = errors.Join(err, export(ctx))
		return err
	}
	for {
		select {
		case span := <-q.queue:
			batch = append(batch, span)
			if len(batch) == q.batch {
				_ = export(q.lifetime)
			}
		case <-ticker.C:
			_ = export(q.lifetime)
		case c := <-q.commands:
			c.result <- drain(c.ctx)
		case ctx := <-q.shutdown:
			q.result = errors.Join(drain(ctx), q.exporter.Shutdown(ctx))
			return
		}
	}
}
