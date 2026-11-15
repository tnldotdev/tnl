package maintenance

import (
	"context"
	"testing"
	"time"
)

func TestRunServiceRunCleanupDrainsAvailableBatches(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	calls := 0
	store := serviceRunStoreFunc(func(_ context.Context, _ time.Time) (int, error) {
		calls++
		if calls == 1 {
			return 1, nil
		}
		cancel()
		return 0, nil
	})
	if err := RunServiceRunCleanup(ctx, store, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("cleanup calls = %d, want 2", calls)
	}
}

func TestRunServiceRunCleanupStopsAfterCanceledBatch(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	calls := 0
	store := serviceRunStoreFunc(func(context.Context, time.Time) (int, error) {
		calls++
		cancel()
		return 1, nil
	})
	if err := RunServiceRunCleanup(ctx, store, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("cleanup continued after cancellation: %d calls", calls)
	}
}

type serviceRunStoreFunc func(context.Context, time.Time) (int, error)

func (f serviceRunStoreFunc) ExpireServiceRuns(ctx context.Context, now time.Time) (int, error) {
	return f(ctx, now)
}
