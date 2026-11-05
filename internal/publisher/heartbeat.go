package publisher

import (
	"context"
	"errors"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/observability"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const heartbeatCallTimeout = 10 * time.Second

const heartbeatInterval = 15 * time.Second

func heartbeatSessionAfterUpdate(
	ctx context.Context,
	authority publicRunAuthority,
	expiresAt time.Time,
	update func([]controlv1.ConnectionAssignment) error,
	interval time.Duration,
) error {
	if interval == 0 {
		interval = heartbeatInterval
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		remaining := time.Until(expiresAt)
		if remaining <= 0 {
			return clientcontrol.ErrStatusConflict
		}
		// a short preparation lease must renew before the usual cadence. waiting
		// or a failed call can never move the last confirmed expiration.
		timer.Reset(min(interval, max(time.Millisecond, remaining/2), remaining))
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
		response, observedHeartbeat, err := heartbeatResponseOnce(ctx, authority, expiresAt)
		if err != nil || ctx.Err() != nil {
			return err
		}
		if update != nil && len(response.PublisherConnections) != 0 {
			if err := update(response.PublisherConnections); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		}
		if observedHeartbeat {
			expiresAt = response.PublishRun.ExpiresAt
			observability.PublisherLease(ctx, expiresAt)
		}
	}
}

func heartbeatResponseOnce(
	ctx context.Context,
	authority publicRunAuthority,
	expiresAt time.Time,
) (controlv1.PublishRunHeartbeat, bool, error) {
	if !time.Now().Before(expiresAt) {
		return heartbeatFallback(expiresAt), false, clientcontrol.ErrStatusConflict
	}
	deadline := time.Now().Add(heartbeatCallTimeout)
	if expiresAt.Before(deadline) {
		deadline = expiresAt
	}
	callCtx, cancel := context.WithDeadline(ctx, deadline)
	callCtx, finish := observability.PublisherOperation(callCtx, "heartbeat")
	publishRunID := authority.identity.PublishRunID
	response, err := authority.client.HeartbeatPublishRun(callCtx, publishRunID, authority.identity.Number, authority.token)
	if err == nil && (callCtx.Err() != nil || !time.Now().Before(expiresAt)) {
		err = context.DeadlineExceeded
	}
	if err == nil {
		err = authority.validateHeartbeat(response)
	}
	finish(err)
	callTimedOut := errors.Is(err, context.DeadlineExceeded) && errors.Is(callCtx.Err(), context.DeadlineExceeded)
	cancel()
	if err == nil {
		return response, true, nil
	}
	if ctx.Err() != nil {
		return heartbeatFallback(expiresAt), false, nil
	}
	// a missed heartbeat is safe only while the last confirmed publish run remains valid.
	if errors.Is(err, clientcontrol.ErrUnavailable) || callTimedOut {
		if time.Now().Before(expiresAt) {
			return heartbeatFallback(expiresAt), false, nil
		}
		return heartbeatFallback(expiresAt), false, clientcontrol.ErrStatusConflict
	}
	return heartbeatFallback(expiresAt), false, err
}

func heartbeatFallback(expiresAt time.Time) controlv1.PublishRunHeartbeat {
	return controlv1.PublishRunHeartbeat{PublishRun: controlv1.PublishRun{ExpiresAt: expiresAt}}
}
