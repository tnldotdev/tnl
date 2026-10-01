package publisher

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const heartbeatCallTimeout = 10 * time.Second

const heartbeatInterval = 15 * time.Second

func heartbeatSessionAfterUpdate(
	ctx context.Context,
	server PublicURLControlClient,
	publicURLID string,
	version uint64,
	publishRunToken credentials.PublishRunToken,
	expiresAt time.Time,
	update func([]controlv1.ConnectionAssignment) error,
	observePolicyDenials func(int64) error,
	interval time.Duration,
) error {
	if interval == 0 {
		interval = heartbeatInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		response, observedHeartbeat, err := heartbeatResponseOnce(ctx, server, publicURLID, version, publishRunToken, expiresAt)
		if err != nil || ctx.Err() != nil {
			return err
		}
		expiresAt = response.PublishRun.ExpiresAt
		if update != nil && len(response.PublisherConnections) != 0 {
			if err := update(response.PublisherConnections); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		}
		if observedHeartbeat && observePolicyDenials != nil {
			if err := observePolicyDenials(response.PolicyDenials); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		}
	}
}

func observeHeartbeatPolicyDenials(
	config Config,
	setup controlv1.PublishRunSetup,
	value int64,
	previous *uint64,
) error {
	if value < 0 || uint64(value) < *previous {
		return errors.New("publisher: server returned an invalid policy denial count")
	}
	current := uint64(value)
	if current == *previous {
		return nil
	}
	*previous = current
	return observe(config, Event{
		Type: EventIPPolicyDenials, PublicURLID: setup.PublicUrl.Id, Hostname: setup.PublicUrl.CanonicalHostname,
		PublishRunNumber: uint64(setup.PublishRun.PublishRunNumber), PolicyDenials: current,
	})
}

func heartbeatResponseOnce(
	ctx context.Context,
	server PublicURLControlClient,
	publicURLID string,
	version uint64,
	publishRunToken credentials.PublishRunToken,
	expiresAt time.Time,
) (controlv1.PublishRunHeartbeat, bool, error) {
	callCtx, cancel := context.WithTimeout(ctx, heartbeatCallTimeout)
	response, err := server.HeartbeatPublishRun(callCtx, publicURLID, version, publishRunToken)
	callTimedOut := errors.Is(err, context.DeadlineExceeded) && errors.Is(callCtx.Err(), context.DeadlineExceeded)
	cancel()
	if err == nil {
		return response, true, nil
	}
	if ctx.Err() != nil {
		return heartbeatFallback(expiresAt), false, nil
	}
	// a missed heartbeat is safe only while the last confirmed publish run remains valid.
	if errors.Is(err, controlclient.ErrUnavailable) || callTimedOut {
		if time.Now().Before(expiresAt) {
			return heartbeatFallback(expiresAt), false, nil
		}
		return heartbeatFallback(expiresAt), false, controlclient.ErrStatusConflict
	}
	return heartbeatFallback(expiresAt), false, err
}

func heartbeatFallback(expiresAt time.Time) controlv1.PublishRunHeartbeat {
	return controlv1.PublishRunHeartbeat{PublishRun: controlv1.PublishRun{ExpiresAt: expiresAt}}
}
