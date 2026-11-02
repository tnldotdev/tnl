package maintenance

import (
	"context"
	"testing"
	"time"
)

type connectorPeerPairStoreFunc func(context.Context, time.Time, int) (int64, error)

func (f connectorPeerPairStoreFunc) CleanupExpiredConnectorPeerPairs(ctx context.Context, now time.Time, limit int) (int64, error) {
	return f(ctx, now, limit)
}

func TestConnectorPeerPairCleanupDrainsBatchesAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	calls := 0
	store := connectorPeerPairStoreFunc(func(call context.Context, now time.Time, limit int) (int64, error) {
		calls++
		if limit != connectorPeerPairCleanupBatch || now.IsZero() || call.Err() != nil {
			t.Fatal("invalid cleanup call", limit, now, call.Err())
		}
		if calls == 3 {
			cancel()
			return 0, nil
		}
		return int64(limit), nil
	})
	if err := RunConnectorPeerPairCleanup(ctx, store, nil); err != nil || calls != 3 {
		t.Fatal("cleanup did not drain batches before waiting", calls, err)
	}
}
