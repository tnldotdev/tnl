package tnldruntime

import (
	"context"
	"testing"
	"time"
)

func TestRunEphemeralPublicURLCleanupDrainsAvailableBatches(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	calls := 0
	store := ephemeralPublicURLStoreFunc(func(_ context.Context, _ time.Time) (int, error) {
		calls++
		if calls == 1 {
			return 1, nil
		}
		cancel()
		return 0, nil
	})
	if err := runEphemeralPublicURLCleanup(ctx, store, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("cleanup calls = %d, want 2", calls)
	}
}

func TestRunEphemeralPublicURLCleanupStopsAfterCanceledBatch(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	calls := 0
	store := ephemeralPublicURLStoreFunc(func(context.Context, time.Time) (int, error) {
		calls++
		cancel()
		return 1, nil
	})
	if err := runEphemeralPublicURLCleanup(ctx, store, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("cleanup continued after cancellation: %d calls", calls)
	}
}

type ephemeralPublicURLStoreFunc func(context.Context, time.Time) (int, error)

func (f ephemeralPublicURLStoreFunc) DeleteExpiredEphemeralPublicURLs(ctx context.Context, now time.Time) (int, error) {
	return f(ctx, now)
}
