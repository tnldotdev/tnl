package tnldruntime

import (
	"context"
	"time"
)

// runBatchCleanup drains available batches before waiting for the next sweep.
// Cancellation always stops the loop, even when the last batch had more work.
func runBatchCleanup(
	ctx context.Context,
	interval time.Duration,
	cleanup func(context.Context, time.Time) (int, error),
	report func(int, error),
) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		count, err := cleanup(ctx, time.Now())
		report(count, err)
		if err == nil && count > 0 && ctx.Err() == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
