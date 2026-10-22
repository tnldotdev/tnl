package supervisor

import (
	"context"
	"sync"
)

// OperationLimiter bounds finite startup/provider operations. waiting callers
// queue in arrival order; cancellation removes a waiter without consuming a slot.
type OperationLimiter struct {
	mu               sync.Mutex
	active, capacity int
	waiters          []chan struct{}
}

func NewOperationLimiter(capacity int) *OperationLimiter {
	return &OperationLimiter{capacity: max(1, capacity)}
}

func (l *OperationLimiter) Acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, context.Cause(ctx)
	}
	if l == nil {
		return func() {}, nil
	}
	l.mu.Lock()
	if l.active < l.capacity && len(l.waiters) == 0 {
		l.active++
		l.mu.Unlock()
	} else {
		ready := make(chan struct{})
		l.waiters = append(l.waiters, ready)
		l.mu.Unlock()
		select {
		case <-ready:
		case <-ctx.Done():
			l.mu.Lock()
			for i, w := range l.waiters {
				if w == ready {
					l.waiters = append(l.waiters[:i], l.waiters[i+1:]...)
					l.mu.Unlock()
					return nil, context.Cause(ctx)
				}
			}
			l.mu.Unlock()
			// the slot was assigned concurrently with cancellation.
			l.release()
			return nil, context.Cause(ctx)
		}
	}
	return sync.OnceFunc(l.release), nil
}

func (l *OperationLimiter) release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.waiters) != 0 {
		ready := l.waiters[0]
		l.waiters = l.waiters[1:]
		close(ready)
	} else {
		l.active--
	}
}
