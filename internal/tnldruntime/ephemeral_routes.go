package tnldruntime

import (
	"context"
	"log"
	"time"
)

const ephemeralRouteCleanupInterval = 30 * time.Second

type ephemeralRouteStore interface {
	DeleteExpiredEphemeralRoutes(context.Context, time.Time) (int, error)
}

func runEphemeralRouteCleanup(ctx context.Context, store ephemeralRouteStore) error {
	ticker := time.NewTicker(ephemeralRouteCleanupInterval)
	defer ticker.Stop()
	for {
		deleted, err := store.DeleteExpiredEphemeralRoutes(ctx, time.Now())
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
