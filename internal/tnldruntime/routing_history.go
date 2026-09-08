package tnldruntime

import (
	"context"
	"log"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

const routingHistoryRetention = 10 * time.Minute

type routingHistoryStore interface {
	AdvanceIngressRoutingRetention(context.Context, time.Time) (uint64, error)
	PruneIngressRoutingHistory(context.Context, uint64) (controlstate.RoutingHistoryPruneResult, error)
}

func runRoutingHistoryCleanup(ctx context.Context, store routingHistoryStore) error {
	var cursor uint64
	var nextFloorCheck time.Time
	for ctx.Err() == nil {
		now := time.Now()
		var err error
		if !now.Before(nextFloorCheck) {
			callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			_, err = store.AdvanceIngressRoutingRetention(callCtx, now.Add(-routingHistoryRetention))
			cancel()
			if err == nil {
				nextFloorCheck = now.Add(30 * time.Second)
			}
		}
		delay := 30 * time.Second
		if err == nil {
			callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			batch, pruneErr := store.PruneIngressRoutingHistory(callCtx, cursor)
			cancel()
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
			log.Printf("routing history cleanup: %v", err)
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
