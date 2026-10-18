package publisher

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"
)

const (
	visitorDecisionLifetime = 2 * time.Minute
	visitorDecisionRefresh  = 30 * time.Second
	visitorDecisionRetry    = 5 * time.Second
	visitorDecisionCapacity = 4096
)

type cachedVisitorDecision[T any] struct {
	value        T
	checkedAt    time.Time
	refreshAfter time.Time
	validUntil   time.Time
}

type visitorDecisionCall[T any] struct {
	done  chan struct{}
	value T
	err   error
}

// visitorDecisionCache keeps only positive, run-local decisions. errors may
// reuse a previously checked result until its hard deadline, never beyond it.
type visitorDecisionCache[T any] struct {
	mu      sync.Mutex
	entries map[[sha256.Size]byte]cachedVisitorDecision[T]
	active  map[[sha256.Size]byte]*visitorDecisionCall[T]
}

func (c *visitorDecisionCache[T]) check(ctx context.Context, key [sha256.Size]byte,
	load func(context.Context) (T, time.Time, bool, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	now := time.Now()
	c.mu.Lock()
	entry, found := c.entries[key]
	usable := found && now.Before(entry.validUntil)
	if usable && now.Before(entry.refreshAfter) {
		c.mu.Unlock()
		return entry.value, nil
	}
	if call := c.active[key]; call != nil {
		c.mu.Unlock()
		if usable {
			return entry.value, nil
		}
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-call.done:
			return call.value, call.err
		}
	}
	if c.active == nil {
		c.active = make(map[[sha256.Size]byte]*visitorDecisionCall[T])
	}
	call := &visitorDecisionCall[T]{done: make(chan struct{})}
	c.active[key] = call
	c.mu.Unlock()

	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	value, expires, allowed, err := load(requestCtx)
	cancel()
	c.mu.Lock()
	if err == nil {
		delete(c.entries, key)
		if allowed && !expires.IsZero() {
			until := now.Add(visitorDecisionLifetime)
			if expires.Before(until) {
				until = expires
			}
			if !until.After(time.Now()) {
				err = errors.New("publisher: visitor decision has expired")
			} else {
				if c.entries == nil {
					c.entries = make(map[[sha256.Size]byte]cachedVisitorDecision[T])
				}
				if len(c.entries) >= visitorDecisionCapacity {
					c.evict(time.Now())
				}
				c.entries[key] = cachedVisitorDecision[T]{value: value, checkedAt: now,
					refreshAfter: earlierDecisionTime(now.Add(visitorDecisionRefresh), until), validUntil: until}
			}
		}
	} else if usable && time.Now().Before(entry.validUntil) {
		entry.refreshAfter = earlierDecisionTime(time.Now().Add(visitorDecisionRetry), entry.validUntil)
		c.entries[key] = entry
		value, err = entry.value, nil
	} else {
		delete(c.entries, key)
	}
	delete(c.active, key)
	call.value, call.err = value, err
	close(call.done)
	c.mu.Unlock()
	return value, err
}

func earlierDecisionTime(first, second time.Time) time.Time {
	if first.Before(second) {
		return first
	}
	return second
}

func (c *visitorDecisionCache[T]) evict(now time.Time) {
	var oldest [sha256.Size]byte
	var since time.Time
	for key, entry := range c.entries {
		if !entry.validUntil.After(now) {
			delete(c.entries, key)
			continue
		}
		if since.IsZero() || entry.checkedAt.Before(since) {
			oldest, since = key, entry.checkedAt
		}
	}
	if len(c.entries) >= visitorDecisionCapacity {
		delete(c.entries, oldest)
	}
}
