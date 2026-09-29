package tnldruntime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

func TestRoutingHistoryCleanupOrderingAndCancellation(t *testing.T) {
	for _, failFloor := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel_after_batch", true: "floor_failure"}[failFloor], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			floorCalled, batches := false, 0
			store := routingHistoryTestStore{
				advance: func(call context.Context, cutoff time.Time) (uint64, error) {
					if _, ok := call.Deadline(); !ok {
						t.Fatal("unbounded floor operation")
					}
					if age := time.Since(cutoff); age < routingHistoryRetention || age > routingHistoryRetention+time.Second {
						t.Fatalf("cutoff age=%s", age)
					}
					floorCalled = true
					if failFloor {
						cancel()
						return 0, errors.New("floor failure")
					}
					return 10, nil
				},
				prune: func(call context.Context, cursor uint64) (controlstate.RoutingHistoryPruneResult, error) {
					if !floorCalled || cursor != 0 {
						t.Fatal("pruned before floor or with invalid initial cursor")
					}
					if _, ok := call.Deadline(); !ok {
						t.Fatal("unbounded prune operation")
					}
					batches++
					cancel()
					return controlstate.RoutingHistoryPruneResult{NextRevision: 10, Scanned: 1000, Deleted: 1000, More: true}, nil
				},
			}
			if err := runRoutingHistoryCleanup(ctx, store, nil); err != nil {
				t.Fatal(err)
			}
			if !floorCalled || batches != map[bool]int{false: 1, true: 0}[failFloor] {
				t.Fatalf("floor=%t batches=%d", floorCalled, batches)
			}
		})
	}
}

type routingHistoryTestStore struct {
	advance func(context.Context, time.Time) (uint64, error)
	prune   func(context.Context, uint64) (controlstate.RoutingHistoryPruneResult, error)
}

func (s routingHistoryTestStore) AdvanceIngressRoutingRetention(ctx context.Context, cutoff time.Time) (uint64, error) {
	return s.advance(ctx, cutoff)
}
func (s routingHistoryTestStore) PruneIngressRoutingHistory(ctx context.Context, after uint64) (controlstate.RoutingHistoryPruneResult, error) {
	return s.prune(ctx, after)
}
