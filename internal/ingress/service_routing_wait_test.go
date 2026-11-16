package ingress

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestServiceRoutingFirstConnectionWaitsOnlyForBackgroundInstallation(t *testing.T) {
	for _, found := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh miss", true: "new run"}[found], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				lease, snapshot := serviceRoutingFixture(t)
				routing := NewServiceRouting()
				defer routing.Close()
				full := snapshot
				snapshot.Runs = nil
				if err := routing.apply(time.Now(), lease, snapshot); err != nil {
					t.Fatal(err)
				}
				time.Sleep(time.Millisecond)
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				deadline, _ := ctx.Deadline()
				done := make(chan error, 2)
				for range 2 {
					go func() { done <- routing.waitForEndpoint(ctx, "route.example", lease) }()
				}
				synctest.Wait()
				select {
				case err := <-done:
					t.Fatal("a stale miss refused the first connection", err)
				default:
				}
				time.Sleep(time.Millisecond)
				snapshot.ObservedAt = time.Now()
				if found {
					snapshot.Runs = full.Runs
				}
				if err := routing.apply(time.Now(), lease, snapshot); err != nil {
					t.Fatal(err)
				}
				for range 2 {
					err := <-done
					if found && err != nil || !found && !errors.Is(err, ErrServiceAdmission) {
						t.Fatal("background installation changed endpoint selection", err)
					}
				}
				if after, _ := ctx.Deadline(); !after.Equal(deadline) || !time.Now().Before(deadline) {
					t.Fatal("routing extended or spent the original setup deadline")
				}
				if found {
					before := time.Now()
					if err := routing.waitForEndpoint(ctx, "route.example", lease); err != nil || !time.Now().Equal(before) {
						t.Fatal("a cache hit waited for another snapshot", err)
					}
				}
			})
		})
	}
}

func TestServiceRoutingFirstConnectionRetainsCancellationAndShutdown(t *testing.T) {
	for _, stop := range []string{"deadline", "caller", "routing", "lease"} {
		t.Run(stop, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				lease, _ := serviceRoutingFixture(t)
				routing := NewServiceRouting()
				defer routing.Close()
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				cause := errors.New("caller stopped setup")
				ctx, stopCaller := context.WithCancelCause(ctx)
				defer stopCaller(nil)
				if stop == "lease" {
					lease.ServingUntil = time.Now()
				}
				done := make(chan error, 1)
				go func() { done <- routing.waitForEndpoint(ctx, "route.example", lease) }()
				synctest.Wait()
				want := ErrServiceAdmission
				switch stop {
				case "deadline":
					time.Sleep(time.Second)
					want = context.DeadlineExceeded
				case "caller":
					stopCaller(cause)
					want = cause
				case "routing":
					routing.Close()
				}
				if err := <-done; !errors.Is(err, want) {
					t.Fatal("routing wait lost its original stop boundary", err)
				}
			})
		})
	}
}
