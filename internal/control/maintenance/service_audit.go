package maintenance

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
)

type serviceAuditCleanupStore interface {
	CleanupServiceAudit(context.Context, time.Time, int) (int64, error)
}

func RunServiceAuditCleanup(ctx context.Context, store serviceAuditCleanupStore, observers ...*observability.Metrics) error {
	var metrics *observability.Metrics
	if len(observers) > 0 {
		metrics = observers[0]
	}
	return runBatchCleanup(ctx, time.Minute, func(ctx context.Context, now time.Time) (int, error) {
		count, err := store.CleanupServiceAudit(ctx, now, 1000)
		metrics.ObserveCleanup("service_audit", int(count), false, err)
		return int(count), err
	}, func(_ int, err error) {
		if err != nil && ctx.Err() == nil {
			operatorlog.ReportContext(ctx, "clean up service audit", failure.ServerWorkerFailed, "", err)
		}
	})
}
