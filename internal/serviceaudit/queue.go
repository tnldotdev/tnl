package serviceaudit

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// a nil result acknowledges every event, including already committed duplicates.
// ambiguous failures retry the same facts; ErrRejected isolates permanent input
// failures. reporters must deduplicate by EventID and honor cancellation.
type Reporter func(context.Context, Batch) error
type Metrics interface{ ServiceAuditCount(string, uint64) }

// ErrRejected marks a permanent rejection. the queue isolates rejected batches
// before dropping individual events; a bad event must not discard its neighbors.
var ErrRejected = errors.New("service audit batch rejected")

type QueueConfig struct {
	Report             Reporter
	Capacity           int
	MaxBytes           int
	BatchSize          int
	FlushInterval      time.Duration
	AttemptTimeout     time.Duration
	ShutdownTimeout    time.Duration
	RetryMin, RetryMax time.Duration
	// max attempts bounds transient failures for each isolated partition.
	MaxAttempts int
	Metrics     Metrics
	// dropped is an aggregate process-local notification, never a per-visitor log.
	Dropped func(uint64)
}

type queued struct {
	event Observation
	bytes int
}
type Queue struct {
	config        QueueConfig
	mu            sync.Mutex
	items         []queued
	bytes         int
	closing       bool
	dropped       uint64
	notify        chan struct{}
	stop          chan struct{}
	done          chan struct{}
	cancel        context.CancelFunc
	stopOnce      sync.Once
	stopParent    func() bool
	parentDone    chan struct{}
	shutdownTimer *time.Timer
	shutdownErr   error
	finished      bool
}

// NewQueue starts one joined reporter. report must honor context cancellation.
// the capacity includes the batch in flight; failures never grow memory.
func NewQueue(ctx context.Context, c QueueConfig) (*Queue, error) {
	if c.Report == nil {
		return nil, errors.New("service audit reporter is required")
	}
	if c.Capacity == 0 {
		c.Capacity = 4096
	}
	if c.MaxBytes == 0 {
		c.MaxBytes = 4 << 20
	}
	if c.BatchSize == 0 {
		c.BatchSize = MaxBatch
	}
	if c.FlushInterval == 0 {
		c.FlushInterval = time.Second
	}
	if c.AttemptTimeout == 0 {
		c.AttemptTimeout = 5 * time.Second
	}
	if c.ShutdownTimeout == 0 {
		c.ShutdownTimeout = 5 * time.Second
	}
	if c.RetryMin == 0 {
		c.RetryMin = 100 * time.Millisecond
	}
	if c.RetryMax == 0 {
		c.RetryMax = 5 * time.Second
	}
	if c.MaxAttempts == 0 {
		c.MaxAttempts = 8
	}
	if c.Capacity < 1 || c.MaxBytes < 2048 || c.BatchSize < 1 || c.BatchSize > MaxBatch || c.FlushInterval <= 0 || c.AttemptTimeout <= 0 || c.ShutdownTimeout <= 0 || c.RetryMin <= 0 || c.RetryMax < c.RetryMin || c.MaxAttempts < 1 || c.MaxAttempts > 32 {
		return nil, ErrInvalid
	}
	life, cancel := context.WithCancel(context.WithoutCancel(ctx))
	q := &Queue{config: c, notify: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}), cancel: cancel, parentDone: make(chan struct{})}
	q.stopParent = context.AfterFunc(ctx, func() { defer close(q.parentDone); q.beginClose() })
	go q.run(life)
	return q, nil
}

func (q *Queue) count(result string, n uint64) {
	if q.config.Metrics != nil && n > 0 {
		q.config.Metrics.ServiceAuditCount(result, n)
	}
}
func (q *Queue) Observe(o Observation) bool {
	err := o.Validate()
	var data []byte
	if err == nil {
		data, err = json.Marshal(o)
	}
	q.mu.Lock()
	if err != nil || len(data) > 2048 || q.closing || len(q.items) >= q.config.Capacity || q.bytes+len(data) > q.config.MaxBytes {
		q.dropped++
		q.mu.Unlock()
		q.count("dropped", 1)
		return false
	}
	q.items = append(q.items, queued{o, len(data)})
	q.bytes += len(data)
	full := len(q.items) >= q.config.BatchSize
	q.mu.Unlock()
	q.count("queued", 1)
	if full {
		select {
		case q.notify <- struct{}{}:
		default:
		}
	}
	return true
}

func (q *Queue) Pending() (int, int) { q.mu.Lock(); defer q.mu.Unlock(); return len(q.items), q.bytes }

func (q *Queue) beginClose() {
	q.stopOnce.Do(func() {
		q.mu.Lock()
		q.closing = true
		q.shutdownTimer = time.AfterFunc(q.config.ShutdownTimeout, func() {
			q.mu.Lock()
			if !q.finished {
				q.shutdownErr = context.DeadlineExceeded
				q.cancel()
			}
			q.mu.Unlock()
		})
		q.mu.Unlock()
		close(q.stop)
	})
}

// Close rejects new observations, flushes accepted ones, and joins the worker.
// a deadline cancels the current request and counts remaining items as dropped.
func (q *Queue) Close(ctx context.Context) error {
	q.beginClose()
	select {
	case <-q.done:
		q.mu.Lock()
		defer q.mu.Unlock()
		return q.shutdownErr
	case <-ctx.Done():
		q.cancel()
		<-q.done
		return ctx.Err()
	}
}

func (q *Queue) run(ctx context.Context) {
	defer close(q.done)
	defer q.cancel()
	defer func() {
		if !q.stopParent() {
			<-q.parentDone
		}
		q.mu.Lock()
		q.finished = true
		if q.shutdownTimer != nil {
			q.shutdownTimer.Stop()
		}
		n := uint64(len(q.items))
		q.items = nil
		q.bytes = 0
		q.closing = true
		q.dropped += n
		dropped := q.dropped
		q.dropped = 0
		q.mu.Unlock()
		q.count("dropped", n)
		if dropped > 0 && q.config.Dropped != nil {
			q.config.Dropped(dropped)
		}
	}()
	timer := time.NewTimer(q.config.FlushInterval)
	defer timer.Stop()
	closing := false
	for {
		if !closing {
			select {
			case <-ctx.Done():
				return
			case <-q.stop:
				closing = true
			case <-q.notify:
			case <-timer.C:
			}
		}
		q.mu.Lock()
		dropped := q.dropped
		q.dropped = 0
		n := min(len(q.items), q.config.BatchSize)
		batch := Batch{Events: make([]Observation, 0, n)}
		size := 16
		for _, item := range q.items[:n] {
			if size+item.bytes+1 > MaxPayloadBytes {
				break
			}
			batch.Events = append(batch.Events, item.event)
			size += item.bytes + 1
		}
		n = len(batch.Events)
		q.mu.Unlock()
		if dropped > 0 && q.config.Dropped != nil {
			q.config.Dropped(dropped)
		}
		if n == 0 {
			if closing {
				return
			}
			timer.Reset(q.config.FlushInterval)
			continue
		}
		if !q.deliver(ctx, batch) {
			return
		}
		q.mu.Lock()
		more := len(q.items) > 0
		q.mu.Unlock()
		if more {
			select {
			case q.notify <- struct{}{}:
			default:
			}
		}
		timer.Reset(q.config.FlushInterval)
	}
}

// deliver retains exact event IDs and timestamps across ambiguous responses.
// splitting takes at most 2*n-1 partitions and logarithmic stack space. each
// partition has a finite retry budget; shutdown independently bounds all work.
// only the worker removes prefixes, including those completed during a split.
func (q *Queue) deliver(ctx context.Context, batch Batch) bool {
	backoff := q.config.RetryMin
	for tries := 1; ; tries++ {
		if ctx.Err() != nil {
			return false
		}
		attempt, cancel := context.WithTimeout(ctx, q.config.AttemptTimeout)
		err := q.config.Report(attempt, batch)
		cancel()
		if err == nil {
			q.finishBatch(len(batch.Events), false)
			return true
		}
		if ctx.Err() != nil {
			return false
		}
		if errors.Is(err, ErrRejected) {
			if len(batch.Events) > 1 {
				middle := len(batch.Events) / 2
				return q.deliver(ctx, Batch{Events: batch.Events[:middle]}) &&
					q.deliver(ctx, Batch{Events: batch.Events[middle:]})
			}
			q.finishBatch(1, true)
			return true
		}
		if tries == q.config.MaxAttempts {
			q.finishBatch(len(batch.Events), true)
			return true
		}
		q.count("retry", 1)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
		backoff = min(backoff*2, q.config.RetryMax)
	}
}

func (q *Queue) finishBatch(n int, dropped bool) {
	q.mu.Lock()
	if dropped {
		q.dropped += uint64(n)
	}
	for _, item := range q.items[:n] {
		q.bytes -= item.bytes
	}
	copy(q.items, q.items[n:])
	clear(q.items[len(q.items)-n:])
	q.items = q.items[:len(q.items)-n]
	q.mu.Unlock()
	if dropped {
		q.count("dropped", uint64(n))
	} else {
		q.count("delivered", uint64(n))
	}
}
