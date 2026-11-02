package maintenance

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
)

const connectorPeerPairCleanupInterval = 30 * time.Second
const connectorPeerPairCleanupBatch = 100

type connectorPeerPairStore interface {
	CleanupExpiredConnectorPeerPairs(context.Context, time.Time, int) (int64, error)
}

// run at startup and periodically after both authority and replay fences expire.
func RunConnectorPeerPairCleanup(ctx context.Context, store connectorPeerPairStore, metrics *observability.Metrics) error {
	return runBatchCleanup(ctx, connectorPeerPairCleanupInterval, func(call context.Context, now time.Time) (int, error) {
		removed, err := store.CleanupExpiredConnectorPeerPairs(call, now, connectorPeerPairCleanupBatch)
		return int(removed), err
	}, func(removed int, err error) {
		metrics.ObserveCleanup("connector_peer_pairs", removed, false, err)
		if err != nil && ctx.Err() == nil {
			operatorlog.ReportContext(ctx, "clean up connector peer pairs", failure.ServerWorkerFailed, "", err)
		}
	})
}
