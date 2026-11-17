package maintenance

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
)

type serviceRunStore interface {
	ExpireServiceRuns(context.Context, time.Time) (int, error)
}

// run on startup as well as periodically so expired runs release relay capacity
// and idle ephemeral services are removed even if no publisher reconnects.
func RunServiceRunCleanup(ctx context.Context, store serviceRunStore, metrics *observability.Metrics) error {
	return runBatchCleanup(ctx, 30*time.Second, store.ExpireServiceRuns, func(closed int, err error) {
		metrics.ObserveCleanup("service_runs", closed, false, err)
		if err != nil && ctx.Err() == nil {
			operatorlog.ReportContext(ctx, "expire service runs", failure.ServerWorkerFailed, "", err)
		}
	})
}
