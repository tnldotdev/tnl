package tunnel

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

const connectorPermissionSuspensionLimit = 30 * time.Second

// ConnectorPermissionGate suspends control delivery while a retained session's
// packet binding is staged. it never changes authority or QUIC idle deadlines.
// repeated suspension can narrow, but cannot extend, the current pause.
type ConnectorPermissionGate struct {
	mu       sync.Mutex
	changed  chan struct{}
	pausedAt time.Time
	until    time.Time
	paused   time.Duration
	err      error
	writing  *connectorPermissionWrite
}

type connectorPermissionWrite struct {
	stream    muxsession.Stream
	authority time.Time
	started   time.Time
	paused    time.Duration
}

func (g *ConnectorPermissionGate) notifyLocked() {
	if g.changed != nil {
		close(g.changed)
	}
	g.changed = make(chan struct{})
}

func (g *ConnectorPermissionGate) pausedLocked(now time.Time) time.Duration {
	paused := g.paused
	if !g.pausedAt.IsZero() {
		paused += minTime(now, g.until).Sub(g.pausedAt)
	}
	return paused
}

func (g *ConnectorPermissionGate) errorLocked(now time.Time) error {
	if g.err == nil && !g.until.IsZero() && !now.Before(g.until) {
		g.err = context.DeadlineExceeded
	}
	return g.err
}

func (g *ConnectorPermissionGate) writeDeadlineLocked(now time.Time) time.Time {
	w := g.writing
	deadline := w.started.Add(2*time.Second + g.pausedLocked(now) - w.paused)
	if !g.until.IsZero() {
		deadline = g.until
	}
	return minTime(w.authority, deadline)
}

// Suspend must run before the short write deadline expires. an expired or failed
// frame is terminal and cannot be made reusable by suspending it afterward.
func (g *ConnectorPermissionGate) Suspend(until time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if err := g.errorLocked(now); err != nil {
		return err
	}
	if !until.After(now) {
		return context.DeadlineExceeded
	}
	if g.writing != nil && !g.writeDeadlineLocked(now).After(now) {
		return context.DeadlineExceeded
	}
	if g.until.IsZero() {
		g.pausedAt = now
		g.until = minTime(until, now.Add(connectorPermissionSuspensionLimit))
	} else {
		g.until = minTime(g.until, until)
	}
	if g.writing != nil {
		g.err = g.writing.stream.SetWriteDeadline(g.writeDeadlineLocked(now))
	}
	g.notifyLocked()
	return g.err
}

// Resume releases delivery only after the caller has authenticated activation.
// accepted ACKs observed during suspension remain fenced until this call.
func (g *ConnectorPermissionGate) Resume() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if err := g.errorLocked(now); err != nil {
		return err
	}
	if g.until.IsZero() {
		return nil
	}
	g.paused = g.pausedLocked(now)
	g.pausedAt, g.until = time.Time{}, time.Time{}
	if g.writing != nil {
		g.err = g.writing.stream.SetWriteDeadline(g.writeDeadlineLocked(now))
	}
	g.notifyLocked()
	return g.err
}

func (g *ConnectorPermissionGate) wait(ctx context.Context) (sharedFailure bool, err error) {
	for {
		g.mu.Lock()
		if g.changed == nil {
			g.changed = make(chan struct{})
		}
		err, until, changed := g.errorLocked(time.Now()), g.until, g.changed
		g.mu.Unlock()
		if err != nil {
			return true, err
		}
		if until.IsZero() {
			return false, context.Cause(ctx)
		}
		timer := time.NewTimer(time.Until(until))
		select {
		case <-ctx.Done():
			timer.Stop()
			return false, context.Cause(ctx)
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// the request owns queueing and its ACK wait. once a frame starts, only the
// shared owner can interrupt it; its write deadline still bounds completion.
// ending one visitor must not reset framing shared by its siblings.
// callers own and join the stream's permanent cancellation/reset callback.
func (g *ConnectorPermissionGate) write(ctx context.Context, stream muxsession.Stream, gate chan struct{}, write func(io.Writer) error) (sharedFailure bool, result error) {
	if shared, err := g.wait(ctx); err != nil {
		return shared, err
	}
	select {
	case gate <- struct{}{}:
	case <-ctx.Done():
		return false, context.Cause(ctx)
	}
	defer func() { <-gate }()
	for {
		if shared, err := g.wait(ctx); err != nil {
			return shared, err
		}
		g.mu.Lock()
		if !g.until.IsZero() {
			g.mu.Unlock()
			continue
		}
		until, ok := ctx.Deadline()
		now := time.Now()
		if cause := context.Cause(ctx); cause != nil {
			g.mu.Unlock()
			return false, cause
		}
		if !ok || !until.After(now) {
			g.mu.Unlock()
			return false, context.DeadlineExceeded
		}
		g.writing = &connectorPermissionWrite{stream: stream, authority: until, started: now, paused: g.pausedLocked(now)}
		result = stream.SetWriteDeadline(g.writeDeadlineLocked(now))
		g.mu.Unlock()
		break
	}
	defer func() {
		g.mu.Lock()
		g.writing = nil
		// latch shared failure before releasing the write gate. a sibling must
		// not start another frame while the caller retires the control owner.
		if result != nil {
			g.err = errors.Join(g.err, result)
			g.notifyLocked()
		}
		result = g.errorLocked(time.Now())
		sharedFailure = result != nil
		g.mu.Unlock()
	}()
	if result != nil {
		return true, result
	}
	result = write(stream)
	if result != nil {
		// never retry a frame after an IO error, including partial writes.
		_ = stream.Reset(0)
		result = errors.Join(result, context.Cause(ctx))
	}
	return result != nil, result
}

func (g *ConnectorPermissionGate) acknowledged(ctx context.Context, result <-chan error) (sharedFailure bool, err error) {
	started := time.Now()
	g.mu.Lock()
	paused := g.pausedLocked(started)
	g.mu.Unlock()
	accepted := false
	for {
		g.mu.Lock()
		if g.changed == nil {
			g.changed = make(chan struct{})
		}
		now := time.Now()
		err, suspended, changed := g.errorLocked(now), !g.until.IsZero(), g.changed
		until := started.Add(10*time.Second + g.pausedLocked(now) - paused)
		budgetExpired := !until.After(now)
		if suspended {
			until = g.until
		}
		g.mu.Unlock()
		if err != nil {
			return true, err
		}
		if !suspended && accepted {
			return false, context.Cause(ctx)
		}
		if budgetExpired || !until.After(now) {
			return false, context.DeadlineExceeded
		}
		timer := time.NewTimer(time.Until(until))
		select {
		case decision := <-result:
			timer.Stop()
			if decision != nil {
				return false, decision
			}
			accepted = true
			result = nil
		case <-ctx.Done():
			timer.Stop()
			return false, context.Cause(ctx)
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
	}
}
