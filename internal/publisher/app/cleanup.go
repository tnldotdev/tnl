package app

import (
	"context"
	"time"
)

// cleanupAttempt owns one bounded cleanup operation, not the registration's
// worker fence. mu protects narrowing; timer callbacks only cancel this attempt.
// the operation owner joins both its parent callback and deadline timer.
type cleanupAttempt struct {
	ctx        context.Context
	cancel     context.CancelCauseFunc
	release    context.CancelFunc
	until      time.Time
	detached   bool
	timer      *time.Timer
	timerDone  chan struct{}
	stopParent func() bool
	parentDone chan struct{}
}

func (m *Manager) beginCleanupLocked(reg *registration, base context.Context, until time.Time, detached bool) *cleanupAttempt {
	bounded, release := context.WithDeadline(base, until)
	ctx, cancel := context.WithCancelCause(bounded)
	a := &cleanupAttempt{ctx: ctx, cancel: cancel, release: release, until: until,
		detached: detached, parentDone: make(chan struct{})}
	reg.cleanup = a
	a.stopParent = context.AfterFunc(m.ctx, func() {
		defer close(a.parentDone)
		m.mu.Lock()
		defer m.mu.Unlock()
		if reg.cleanup == a && m.ShutdownDeadline != nil {
			a.limit(m.ShutdownDeadline())
		}
	})
	if (m.closed || m.ctx.Err() != nil) && m.ShutdownDeadline != nil {
		a.limit(m.ShutdownDeadline())
	}
	return a
}

func (a *cleanupAttempt) limit(until time.Time) {
	if !until.Before(a.until) {
		return
	}
	a.stopTimer()
	a.until = until
	if !time.Now().Before(until) {
		a.cancel(context.DeadlineExceeded)
		return
	}
	done, cancel := make(chan struct{}), a.cancel
	a.timerDone = done
	a.timer = time.AfterFunc(time.Until(until), func() {
		defer close(done)
		cancel(context.DeadlineExceeded)
	})
}

func (a *cleanupAttempt) stopTimer() {
	if a.timer != nil {
		if a.timer.Stop() {
			close(a.timerDone)
		}
		<-a.timerDone
		a.timer, a.timerDone = nil, nil
	}
}

func (m *Manager) finishCleanup(reg *registration, a *cleanupAttempt) error {
	// the parent callback needs mu, so join it before taking the manager lock.
	if !a.stopParent() {
		<-a.parentDone
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if (m.closed || m.ctx.Err() != nil) && m.ShutdownDeadline != nil {
		a.limit(m.ShutdownDeadline())
	}
	if !time.Now().Before(a.until) {
		a.cancel(context.DeadlineExceeded)
	}
	a.stopTimer()
	cause := context.Cause(a.ctx)
	a.cancel(context.Canceled)
	a.release()
	if reg.cleanup == a {
		reg.cleanup = nil
	}
	// successful local retirement cancels the old registration fence after its
	// final write. that expected owner stop is not another cleanup failure.
	if cause == context.Canceled {
		return nil
	}
	return cause
}
