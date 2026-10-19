package controlstate

import (
	"context"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability"
)

// RefreshPortPoolMetrics reads committed inventory on a worker, never a scrape.
// held includes private services; a quarantined port stays unavailable until
// control releases it, regardless of an observer's clock.
func (d *Database) RefreshPortPoolMetrics(ctx context.Context, metrics *observability.Metrics) error {
	rows, err := controlstatedb.New(d.pool).ServicePortPoolCapacity(ctx)
	if err != nil {
		return err
	}
	for _, row := range rows {
		metrics.SetTCPPortPoolCapacity(row.IngressPoolID, row.Configured, row.Claimed, row.Quarantined, row.Available)
	}
	return nil
}
