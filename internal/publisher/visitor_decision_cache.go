package publisher

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
)

const (
	visitorDecisionLifetime = 2 * time.Minute
	visitorDecisionRefresh  = 30 * time.Second
	visitorDecisionRecheck  = visitorDecisionRefresh - 5*time.Second
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
	done      chan struct{}
	value     T
	checkedAt time.Time
	err       error
}

// visitorDecisionCache keeps only positive, run-local decisions. structured
// unavailability may reuse the last success until its hard deadline.
type visitorDecisionCache[T any] struct {
	mu       sync.Mutex
	revision int64
	entries  map[[sha256.Size]byte]cachedVisitorDecision[T]
	active   map[[sha256.Size]byte]*visitorDecisionCall[T]
}

// invalidate also fences in-flight decisions checked under the old policy.
func (c *visitorDecisionCache[T]) invalidate(revision int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if revision <= c.revision {
		return
	}
	c.revision = revision
	clear(c.entries)
}

func (c *visitorDecisionCache[T]) check(ctx context.Context, key [sha256.Size]byte,
	load func(context.Context) (T, time.Time, bool, error)) (T, error) {
	value, _, err := c.checkCurrent(ctx, key, false, load)
	return value, err
}

func (c *visitorDecisionCache[T]) checkCurrent(ctx context.Context, key [sha256.Size]byte, refresh bool,
	load func(context.Context) (T, time.Time, bool, error)) (T, time.Time, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, time.Time{}, err
	}
	now := time.Now()
	c.mu.Lock()
	revision := c.revision
	entry, found := c.entries[key]
	usable := found && now.Before(entry.validUntil)
	if !refresh && usable && now.Before(entry.refreshAfter) {
		c.mu.Unlock()
		return entry.value, entry.checkedAt, nil
	}
	if call := c.active[key]; call != nil {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return zero, time.Time{}, ctx.Err()
		case <-call.done:
			return call.value, call.checkedAt, call.err
		}
	}
	if c.active == nil {
		c.active = make(map[[sha256.Size]byte]*visitorDecisionCall[T])
	}
	call := &visitorDecisionCall[T]{done: make(chan struct{})}
	c.active[key] = call
	c.mu.Unlock()

	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	checkedAt := now
	value, expires, allowed, err := load(requestCtx)
	cancel()
	c.mu.Lock()
	if revision != c.revision {
		// the old result and outage fallback must not restore revoked access.
		value, err = zero, errors.New("publisher: visitor authority changed; retry the request")
	} else if err == nil {
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
					refreshAfter: earlierDecisionTime(now.Add(visitorDecisionRecheck), until), validUntil: until}
			}
		}
	} else if errors.Is(err, controlclient.ErrUnavailable) && usable && time.Now().Before(entry.validUntil) {
		entry.refreshAfter = earlierDecisionTime(time.Now().Add(visitorDecisionRetry), entry.validUntil)
		c.entries[key] = entry
		value, err = entry.value, nil
		checkedAt = entry.checkedAt
	} else {
		delete(c.entries, key)
	}
	delete(c.active, key)
	call.value, call.checkedAt, call.err = value, checkedAt, err
	close(call.done)
	c.mu.Unlock()
	return value, checkedAt, err
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
