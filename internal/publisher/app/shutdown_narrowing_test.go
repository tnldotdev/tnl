package app

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
)

func TestManagerLateShutdownLimitBoundsActivePublicationCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		workers, ready := testWorkers(t)
		configure := workers.Configure
		cleaning := make(chan context.Context)
		joined := make(chan time.Time, 1)
		cleanupFailure := errors.New("independent allocation cleanup failure")
		operationFailure := errors.New("independent service operation failure")
		workers.Configure = func(ctx context.Context, service Service) (Configuration, error) {
			cfg, err := configure(ctx, service)
			run := cfg.Service.Run
			cfg.Service.Run = func(ctx context.Context, tunnel *clientstate.Tunnel, observe func(uint64, bool) error, summary inspection.Observer) error {
				return errors.Join(run(ctx, tunnel, observe, summary), operationFailure)
			}
			cfg.Cleanup = func(finish context.Context) error {
				cleaning <- finish
				<-finish.Done()
				joined <- time.Now()
				return errors.Join(finish.Err(), cleanupFailure)
			}
			return cfg, err
		}
		const target = "http://127.0.0.1:3000"
		id := registerServicePublication(t, workers, target, "")
		<-ready
		done := make(chan error, 1)
		go func() { done <- workers.Manager.UnregisterTarget(id, "owner", target) }()
		active := <-cleaning
		first, ok := active.Deadline()
		if !ok || time.Until(first) != 10*time.Second {
			t.Fatal("publication cleanup did not begin with its original ten-second budget", first)
		}
		time.Sleep(time.Second)
		until := time.Now().Add(2 * time.Second)
		// the native API applies this exact-owner limit before joining a
		// concurrent unregister retry; it does not need the first call's op lock.
		if err := workers.Manager.LimitShutdown(id, "owner", target, until); err != nil {
			t.Fatal(err)
		}
		if err := workers.Manager.LimitShutdown(id, "owner", target, until.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if got := workers.Manager.PublicationShutdownDeadline(id); !got.Equal(until) {
			t.Fatal("exact registration did not retain its narrowed deadline", got, until)
		}
		time.Sleep(time.Until(until))
		synctest.Wait()
		if got, _ := active.Deadline(); !got.Equal(first) || active.Err() != context.Canceled || context.Cause(active) != context.DeadlineExceeded {
			t.Error("active cleanup did not retain standard context deadline/cause behavior", got, active.Err(), context.Cause(active))
		}
		var joinedAt time.Time
		select {
		case joinedAt = <-joined:
		default:
			t.Error("active publication cleanup did not stop at the exact registration's narrowed deadline")
		}
		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, cleanupFailure) || !errors.Is(err, operationFailure) {
				t.Error("unregister lost timeout or independent allocation failure", err)
			}
		default:
			t.Error("unregister remained blocked beyond the narrowed deadline")
			err := <-done
			if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, cleanupFailure) || !errors.Is(err, operationFailure) {
				t.Error("late unregister lost timeout or independent allocation failure", err)
			}
		}
		if joinedAt.IsZero() {
			joinedAt = <-joined
		}
		if joinedAt.After(until) {
			t.Errorf("publication cleanup joined %s after its narrowed deadline", joinedAt.Sub(until))
		}
	})
}
