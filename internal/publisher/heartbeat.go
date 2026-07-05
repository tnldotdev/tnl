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

var heartbeatInterval = 15 * time.Second

func heartbeatSessionAfterUpdate(
	ctx context.Context,
	server RouteControlClient,
	routeID string,
	version uint64,
	routeSessionToken credentials.RouteSessionToken,
	expiresAt time.Time,
	update func([]controlv1.ConnectionAssignment) error,
	observePolicyDenials func(int64) error,
) error {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		response, observedHeartbeat, err := heartbeatResponseOnce(ctx, server, routeID, version, routeSessionToken, expiresAt)
		if err != nil || ctx.Err() != nil {
			return err
		}
		expiresAt = response.RouteSession.ExpiresAt
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
	setup controlv1.RouteSessionSetup,
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
		Type: EventIPPolicyDenials, RouteID: setup.Route.Id, Hostname: setup.Route.CanonicalHostname,
		RouteVersion: uint64(setup.RouteSession.RouteVersion), PolicyDenials: current,
	})
}

func heartbeatResponseOnce(
	ctx context.Context,
	server RouteControlClient,
	routeID string,
	version uint64,
	routeSessionToken credentials.RouteSessionToken,
	expiresAt time.Time,
) (controlv1.RouteSessionHeartbeat, bool, error) {
	callCtx, cancel := context.WithTimeout(ctx, heartbeatCallTimeout)
	response, err := server.HeartbeatRouteSession(callCtx, routeID, version, routeSessionToken)
	cancel()
	if err == nil {
		return response, true, nil
	}
	if ctx.Err() != nil {
		return heartbeatFallback(expiresAt), false, nil
	}
	// A missed heartbeat is safe only while the last confirmed session remains valid.
	if errors.Is(err, controlclient.ErrUnavailable) && time.Now().Before(expiresAt) {
		return heartbeatFallback(expiresAt), false, nil
	}
	if errors.Is(err, controlclient.ErrUnavailable) {
		return heartbeatFallback(expiresAt), false, controlclient.ErrStatusConflict
	}
	return heartbeatFallback(expiresAt), false, err
}

func heartbeatFallback(expiresAt time.Time) controlv1.RouteSessionHeartbeat {
	return controlv1.RouteSessionHeartbeat{RouteSession: controlv1.RouteSession{ExpiresAt: expiresAt}}
}
