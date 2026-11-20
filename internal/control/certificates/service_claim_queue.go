package certificates

import (
	"context"
	"time"
)

// ServiceClaimQueue coordinates claims, not issuance. each control process
// shares one queue among its service certificate workers.
type ServiceClaimQueue struct {
	turn chan time.Time
}

func NewServiceClaimQueue() *ServiceClaimQueue {
	queue := &ServiceClaimQueue{turn: make(chan time.Time, 1)}
	queue.turn <- time.Time{}
	return queue
}

func (q *ServiceClaimQueue) take(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case next := <-q.turn:
		if !waitForServiceClaim(ctx, time.Until(next)) {
			q.turn <- next
			return false
		}
		return true
	}
}

func (q *ServiceClaimQueue) release(found bool, idle time.Duration) {
	next := time.Time{}
	if !found {
		next = time.Now().Add(idle)
	}
	q.turn <- next
}

func waitForServiceClaim(ctx context.Context, delay time.Duration) bool {
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
		}
	}
	return ctx.Err() == nil
}
