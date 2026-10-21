package tnldruntime

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/workerloop"
)

type workloadCleanupStore interface {
	CleanupWorkloads(context.Context, time.Time, int) (int64, error)
}

func runWorkloadCleanup(ctx context.Context, store workloadCleanupStore, metrics *observability.Metrics) error {
	return workerloop.Run(ctx, workerloop.Config{
		OperationTimeout: 5 * time.Second,
		IdleInterval:     time.Minute,
		Process: func(ctx context.Context) (bool, error) {
			count, err := store.CleanupWorkloads(ctx, time.Now(), 1000)
			metrics.ObserveCleanup("workloads", int(count), false, err)
			return count > 0, err
		},
		OnError: func(err error) {
			if ctx.Err() == nil {
				logOperationalError(ctx, "clean up workload history", failure.ServerWorkerFailed, err)
			}
		},
	})
}
