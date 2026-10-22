package maintenance

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
)

const ephemeralPublicURLCleanupInterval = 30 * time.Second

type ephemeralPublicURLStore interface {
	DeleteExpiredEphemeralPublicURLs(context.Context, time.Time) (int, error)
}

func RunEphemeralPublicURLCleanup(ctx context.Context, store ephemeralPublicURLStore, metrics *observability.Metrics) error {
	return runBatchCleanup(ctx, ephemeralPublicURLCleanupInterval, store.DeleteExpiredEphemeralPublicURLs, func(deleted int, err error) {
		metrics.ObserveCleanup("ephemeral_public_urls", deleted, false, err)
		if err != nil && ctx.Err() == nil {
			operatorlog.ReportContext(ctx, "clean up ephemeral public URLs", failure.ServerWorkerFailed, "", err)
		}
	})
}
