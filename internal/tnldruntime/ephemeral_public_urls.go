package tnldruntime

import (
	"context"
	"log"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

const ephemeralRouteCleanupInterval = 30 * time.Second

type ephemeralRouteStore interface {
	DeleteExpiredEphemeralPublicURLs(context.Context, time.Time) (int, error)
}

func runEphemeralRouteCleanup(ctx context.Context, store ephemeralRouteStore, metrics *observability.Metrics) error {
	ticker := time.NewTicker(ephemeralRouteCleanupInterval)
	defer ticker.Stop()
	for {
		deleted, err := store.DeleteExpiredEphemeralPublicURLs(ctx, time.Now())
		metrics.ObserveCleanup("ephemeral_public_urls", deleted, false, err)
		if err != nil && ctx.Err() == nil {
			log.Printf("ephemeral route cleanup: %v", err)
		}
		if err == nil && deleted > 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
