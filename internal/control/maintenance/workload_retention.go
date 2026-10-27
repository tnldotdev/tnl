package maintenance

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
	"github.com/tnldotdev/tnl/internal/workerloop"
)

type workloadCleanupStore interface {
	CleanupWorkloads(context.Context, time.Time, int) (int64, error)
	CleanupExpiredNativePeerPairs(context.Context, time.Time, int) (int64, error)
}

func RunWorkloadCleanup(ctx context.Context, store workloadCleanupStore, metrics *observability.Metrics) error {
	return workerloop.Run(ctx, workerloop.Config{
		OperationTimeout: 5 * time.Second,
		IdleInterval:     time.Minute,
		Process: func(ctx context.Context) (bool, error) {
			now := time.Now()
			pairs, pairErr := store.CleanupExpiredNativePeerPairs(ctx, now, 1000)
			metrics.ObserveCleanup("native_peer_pairs", int(pairs), false, pairErr)
			workloads, workloadErr := store.CleanupWorkloads(ctx, now, 1000)
			metrics.ObserveCleanup("workloads", int(workloads), false, workloadErr)
			return workloads > 0 || pairs > 0, errors.Join(workloadErr, pairErr)
		},
		OnError: func(err error) {
			if ctx.Err() == nil {
				operatorlog.ReportContext(ctx, "clean up workload history and native peer pairs", failure.ServerWorkerFailed, "", err)
			}
		},
	})
}
