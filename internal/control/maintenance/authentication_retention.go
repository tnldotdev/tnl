package maintenance

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
	"github.com/tnldotdev/tnl/internal/workerloop"
)

type authenticationCleanupStore interface {
	CleanupAuthentication(context.Context, time.Time, int) (int64, error)
}

func RunAuthenticationCleanup(ctx context.Context, store authenticationCleanupStore) error {
	return workerloop.Run(ctx, workerloop.Config{
		OperationTimeout: 5 * time.Second,
		IdleInterval:     time.Minute,
		Process: func(ctx context.Context) (bool, error) {
			count, err := store.CleanupAuthentication(ctx, time.Now(), 1000)
			return count > 0, err
		},
		OnError: func(err error) {
			if ctx.Err() == nil {
				operatorlog.ReportContext(ctx, "clean up expired authentication", failure.ServerWorkerFailed, "", err)
			}
		},
	})
}
