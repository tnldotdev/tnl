package workload

import (
	"context"
	"time"
)

// Maintain renews an exchanged session for a caller without the native IPC owner.
// the client remains the sole authority for renewal proofs, response validation,
// immutable scope and fixed expiry. cancellation and renewal failure are final;
// this function never exchanges a replacement identity or starts a second key.
func (c *Client) Maintain(ctx context.Context) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		session, err := c.Session()
		if err != nil {
			return err
		}
		until := SessionDeadline(session)
		if session.LeaseExpiresAt.Before(until) {
			until = session.LeaseExpiresAt
		}
		if !until.After(time.Now()) {
			return ErrSessionExpired
		}
		timer := time.NewTimer(time.Until(until))
		select {
		case <-ctx.Done():
			timer.Stop()
			return context.Cause(ctx)
		case <-timer.C:
			return ErrSessionExpired
		case <-ticker.C:
			timer.Stop()
		}
		call, stop := context.WithDeadline(ctx, until)
		_, err = c.Renew(call)
		stop()
		if err != nil {
			return err
		}
	}
}
