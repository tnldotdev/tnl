package tnldruntime

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
)

const expiredPublishRunCleanupInterval = 30 * time.Second

type expiredPublishRunStore interface {
	ExpireSavedPublishRuns(context.Context, time.Time) (int, error)
}

// run on startup as well as periodically: a control restart must not leave
// saved expired runs reserving relay capacity until their public URLs are used.
func runExpiredPublishRunCleanup(ctx context.Context, store expiredPublishRunStore, metrics *observability.Metrics) error {
	return runBatchCleanup(ctx, expiredPublishRunCleanupInterval, store.ExpireSavedPublishRuns, func(closed int, err error) {
		metrics.ObserveCleanup("expired_publish_runs", closed, false, err)
		if err != nil && ctx.Err() == nil {
			logOperationalError("expire publish runs", failure.ServerWorkerFailed, err)
		}
	})
}
