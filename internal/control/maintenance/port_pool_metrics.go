package maintenance

import (
	"context"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
)

func RunPortPoolMetrics(ctx context.Context, database *controlstate.Database, metrics *observability.Metrics) error {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
		attempt, finish := observability.WorkerAttempt(attempt, "capacity.refresh")
		err := database.RefreshPortPoolMetrics(attempt, metrics)
		if err != nil && ctx.Err() == nil {
			operatorlog.ReportContext(attempt, "refresh service port capacity", failure.ServerWorkerFailed, "", err)
		}
		finish(err)
		cancel()
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
