package tnldruntime

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
)

type idlePublicURLStore interface {
	RetireIdlePublicURLs(context.Context, time.Time) (int, error)
}

func runIdlePublicURLCleanup(ctx context.Context, store idlePublicURLStore, metrics *observability.Metrics) error {
	return runBatchCleanup(ctx, time.Minute, store.RetireIdlePublicURLs, func(deleted int, err error) {
		metrics.ObserveCleanup("saved_public_urls", deleted, false, err)
		if err != nil && ctx.Err() == nil {
			logOperationalError("retire idle public URLs", failure.ServerWorkerFailed, err)
		}
	})
}
