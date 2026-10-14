package tnldruntime

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
)

type operatorIPExpiryStore interface {
	ExpireOperatorIPEntries(context.Context, time.Time) (int, error)
}

func runOperatorIPEntryCleanup(ctx context.Context, store operatorIPExpiryStore, metrics *observability.Metrics) error {
	return runBatchCleanup(ctx, 2*time.Second, store.ExpireOperatorIPEntries, func(expired int, err error) {
		metrics.ObserveCleanup("operator_ip_entries", expired, false, err)
		if err != nil && ctx.Err() == nil {
			logOperationalError("expire operator IP entries", failure.ServerWorkerFailed, err)
		}
	})
}
