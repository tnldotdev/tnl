package tnldruntime

import (
	"context"
	"testing"
	"time"
)

func TestRunEphemeralRouteCleanupDrainsAvailableBatches(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	calls := 0
	store := ephemeralRouteStoreFunc(func(_ context.Context, _ time.Time) (int, error) {
		calls++
		if calls == 1 {
			return 1, nil
		}
		cancel()
		return 0, nil
	})
	if err := runEphemeralRouteCleanup(ctx, store, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("cleanup calls = %d, want 2", calls)
	}
}

type ephemeralRouteStoreFunc func(context.Context, time.Time) (int, error)

func (f ephemeralRouteStoreFunc) DeleteExpiredEphemeralPublicURLs(ctx context.Context, now time.Time) (int, error) {
	return f(ctx, now)
}
