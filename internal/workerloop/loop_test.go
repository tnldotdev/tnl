package workerloop

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestRunDrainsWorkAndWaitsAfterEmptyOrFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		calls := make(chan int, 4)
		failure := errors.New("temporary failure")
		var attempts atomic.Int32
		reported := make(chan error, 1)
		done := make(chan error, 1)
		go func() {
			done <- Run(ctx, Config{OperationTimeout: 5 * time.Second, IdleInterval: time.Second,
				Process: func(operationCtx context.Context) (bool, error) {
					if deadline, ok := operationCtx.Deadline(); !ok || time.Until(deadline) != 5*time.Second {
						t.Errorf("iteration deadline = %v, set = %t", deadline, ok)
					}
					attempt := int(attempts.Add(1))
					calls <- attempt
					switch attempt {
					case 1:
						return true, nil
					case 2:
						return false, nil
					case 3:
						return true, failure
					default:
						cancel()
						return true, nil
					}
				}, OnError: func(err error) { reported <- err }})
		}()
		if got := <-calls; got != 1 {
			t.Fatalf("first iteration = %d", got)
		}
		if got := <-calls; got != 2 {
			t.Fatalf("work did not drain immediately: iteration %d", got)
		}
		synctest.Wait()
		if got := attempts.Load(); got != 2 {
			t.Fatalf("empty iteration did not wait: %d attempts", got)
		}
		time.Sleep(time.Second)
		if got := <-calls; got != 3 {
			t.Fatalf("retry after empty iteration = %d", got)
		}
		if err := <-reported; !errors.Is(err, failure) {
			t.Fatalf("reported error = %v", err)
		}
		synctest.Wait()
		if got := attempts.Load(); got != 3 {
			t.Fatalf("failed iteration did not wait: %d attempts", got)
		}
		time.Sleep(time.Second)
		if got := <-calls; got != 4 {
			t.Fatalf("retry after failure = %d", got)
		}
		if err := <-done; err != nil || attempts.Load() != 4 {
			t.Fatalf("canceled worker returned %v after %d attempts", err, attempts.Load())
		}
	})
}

func TestRunAlreadyCanceledDoesNotProcess(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	calls := 0
	config := Config{
		OperationTimeout: time.Second,
		IdleInterval:     time.Second,
		Process: func(context.Context) (bool, error) {
			calls++
			return false, nil
		},
	}
	for range 64 {
		if err := Run(ctx, config); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 0 {
		t.Fatalf("processed %d iterations after cancellation", calls)
	}
}
