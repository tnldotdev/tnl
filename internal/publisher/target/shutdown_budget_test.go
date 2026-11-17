package target

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTargetReplacementDoesNotStartProcessShutdownBudget(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		changed := make(chan struct{})
		var calls atomic.Int32
		until := sync.OnceValue(func() time.Time {
			calls.Add(1)
			return time.Now().Add(10 * time.Second)
		})
		deadline := targetRunShutdownDeadline(ctx, changed, until)
		if replacement {
			close(changed)
			if got := deadline(); !got.IsZero() || calls.Load() != 0 {
				t.Fatal("replacement consumed the process-exit budget", got, calls.Load())
			}
		}
		cancel()
		if got := deadline(); !got.Equal(until()) || calls.Load() != 1 {
			t.Fatal("process shutdown did not retain the original deadline", got, until(), calls.Load())
		}
	}
}
