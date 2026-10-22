package state

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability"
)

// RefreshPortPoolMetrics reads committed inventory on a worker, never a scrape.
// held includes services; a quarantined port stays unavailable until
// control releases it, regardless of an observer's clock.
func (d *Database) RefreshPortPoolMetrics(ctx context.Context, metrics *observability.Metrics) (retErr error) {
	ctx, finish := observability.ControlOperation(observability.WithMetrics(ctx, metrics), "RefreshPortPoolMetrics")
	defer func() { finish(retErr) }()
	rows, err := controlstatedb.New(d.pool).ServicePortPoolCapacity(ctx)
	if err != nil {
		return err
	}
	pools := make([]observability.PortPoolCapacity, 0, len(rows))
	for _, row := range rows {
		pools = append(pools, observability.PortPoolCapacity{Pool: row.IngressPoolID, Configured: row.Configured, Claimed: row.Claimed, Quarantined: row.Quarantined, Available: row.Available})
	}
	metrics.ReplacePortPoolCapacity(pools, time.Now())
	return nil
}
