package tnldruntime

import (
	"context"
	"log"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

const expiredPublishRunCleanupInterval = 30 * time.Second

type expiredPublishRunStore interface {
	ExpireSavedPublishRuns(context.Context, time.Time) (int, error)
}

// Run on startup as well as periodically: a control restart must not leave
// saved expired runs reserving relay capacity until their public URLs are used.
func runExpiredPublishRunCleanup(ctx context.Context, store expiredPublishRunStore, metrics *observability.Metrics) error {
	ticker := time.NewTicker(expiredPublishRunCleanupInterval)
	defer ticker.Stop()
	for {
		closed, err := store.ExpireSavedPublishRuns(ctx, time.Now())
		metrics.ObserveCleanup("expired_publish_runs", closed, false, err)
		if err != nil && ctx.Err() == nil {
			log.Printf("expired publish run cleanup: %v", err)
		}
		if err == nil && closed > 0 && ctx.Err() == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
