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
	// a short remaining guest budget can bound preparation leases below the
	// ordinary heartbeat interval. renew before that issued horizon, without
	// assuming that control will extend it after readiness or during an outage.
	next := func() time.Duration {
		remaining := time.Until(expiresAt)
		return min(interval, remaining, max(time.Millisecond, remaining/2))
	}
	timer := time.NewTimer(next())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
		if !time.Now().Before(expiresAt) {
			return clientcontrol.ErrStatusConflict
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
		timer.Reset(next())
	}
}

func heartbeatResponseOnce(
	ctx context.Context,
	authority publicRunAuthority,
	expiresAt time.Time,
) (controlv1.PublishRunHeartbeat, bool, error) {
	callCtx, cancel := context.WithTimeout(ctx, heartbeatCallTimeout)
	callCtx, finish := observability.PublisherOperation(callCtx, "heartbeat")
	publishRunID := authority.identity.PublishRunID
	response, err := authority.client.HeartbeatPublishRun(callCtx, publishRunID, authority.identity.Number, authority.token)
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
