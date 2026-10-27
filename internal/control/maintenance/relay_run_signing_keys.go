package maintenance

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
	"github.com/tnldotdev/tnl/internal/workerloop"
)

type relayRunSigningKeyCleanupStore interface {
	CleanupRelayRunSigningKeys(context.Context, time.Time, int) (int64, error)
}

func RunRelayRunSigningKeyCleanup(ctx context.Context, store relayRunSigningKeyCleanupStore, metrics *observability.Metrics) error {
	return workerloop.Run(ctx, workerloop.Config{
		OperationTimeout: 5 * time.Second,
		IdleInterval:     time.Minute,
		Process: func(ctx context.Context) (bool, error) {
			count, err := store.CleanupRelayRunSigningKeys(ctx, time.Now(), 1000)
			metrics.ObserveCleanup("relay_run_signing_keys", int(count), false, err)
			return count > 0, err
		},
		OnError: func(err error) {
			if ctx.Err() == nil {
				operatorlog.ReportContext(ctx, "clean up relay run signing keys", failure.ServerWorkerFailed, "", err)
			}
		},
	})
}
