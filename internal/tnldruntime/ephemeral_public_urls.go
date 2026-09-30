package tnldruntime

import (
	"context"
	"log"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

const ephemeralPublicURLCleanupInterval = 30 * time.Second

type ephemeralPublicURLStore interface {
	DeleteExpiredEphemeralPublicURLs(context.Context, time.Time) (int, error)
}

func runEphemeralPublicURLCleanup(ctx context.Context, store ephemeralPublicURLStore, metrics *observability.Metrics) error {
	return runBatchCleanup(ctx, ephemeralPublicURLCleanupInterval, store.DeleteExpiredEphemeralPublicURLs, func(deleted int, err error) {
		metrics.ObserveCleanup("ephemeral_public_urls", deleted, false, err)
		if err != nil && ctx.Err() == nil {
			log.Printf("ephemeral public URL cleanup: %v", err)
		}
	})
}
