package tnldruntime

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
)

const routingHistoryRetention = 10 * time.Minute

type routingHistoryStore interface {
	AdvanceIngressRoutingRetention(context.Context, time.Time) (uint64, error)
	PruneIngressRoutingHistory(context.Context, uint64) (controlstate.RoutingHistoryPruneResult, error)
}

func runRoutingHistoryCleanup(ctx context.Context, store routingHistoryStore, metrics *observability.Metrics) error {
	var cursor uint64
	var nextFloorCheck time.Time
	for ctx.Err() == nil {
		now := time.Now()
		var err error
		if !now.Before(nextFloorCheck) {
			callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			_, err = store.AdvanceIngressRoutingRetention(callCtx, now.Add(-routingHistoryRetention))
			cancel()
			metrics.ObserveCleanup("routing_floor", 0, false, err)
			if err == nil {
				nextFloorCheck = now.Add(30 * time.Second)
			}
		}
		delay := 30 * time.Second
		if err == nil {
			// the retention floor commits before pruning; a failed batch keeps
			// its cursor so the next pass does not skip unswept history.
			callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			batch, pruneErr := store.PruneIngressRoutingHistory(callCtx, cursor)
			cancel()
			metrics.ObserveCleanup("routing_prune", 0, batch.Busy, pruneErr)
			err = pruneErr
			if err == nil && !batch.Busy {
				cursor = batch.NextRevision
				if batch.More {
					delay = 100 * time.Millisecond
				} else {
					cursor = 0
				}
			}
		}
		if err != nil && ctx.Err() == nil {
			logOperationalError("clean up routing history", failure.ServerWorkerFailed, err)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return nil
}
