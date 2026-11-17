package service

import (
	"context"
	"time"
)

// cleanup retains this operation's values and first local deadline while the
// composing owner's fence can interrupt work already in flight at an earlier
// expiry. the returned join preserves that expiry cause, not just Canceled.
func (c RunConfig) cleanupContext(ctx context.Context, until time.Time) (context.Context, func() error) {
	bounded, cancel := context.WithDeadline(context.WithoutCancel(ctx), until)
	if c.ShutdownContext == nil {
		return bounded, func() error {
			cause := context.Cause(bounded)
			cancel()
			return cause
		}
	}
	finish, expire := context.WithCancelCause(bounded)
	done := make(chan struct{})
	stop := context.AfterFunc(c.ShutdownContext, func() {
		defer close(done)
		expire(context.Cause(c.ShutdownContext))
	})
	if cause := context.Cause(c.ShutdownContext); cause != nil {
		expire(cause)
	}
	return finish, func() error {
		if !stop() {
			<-done
		}
		// stopping an already-scheduled callback must not discard a parent
		// expiry that won concurrently with otherwise successful cleanup.
		if cause := context.Cause(c.ShutdownContext); cause != nil {
			expire(cause)
		}
		cause := context.Cause(finish)
		expire(context.Canceled)
		cancel()
		return cause
	}
}
