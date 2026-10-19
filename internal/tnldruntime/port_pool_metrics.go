package tnldruntime

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/observability"
)

func runPortPoolMetrics(ctx context.Context, database *controlstate.Database, metrics *observability.Metrics) error {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
		started := time.Now()
		err := database.RefreshPortPoolMetrics(attempt, metrics)
		metrics.ObserveOperation("RefreshPortPoolMetrics", err, time.Since(started))
		cancel()
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
