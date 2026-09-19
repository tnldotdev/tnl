package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestStopRoutesBoundsConcurrencyAndCountsActualOutcomes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var active, peak, snapshots atomic.Int32
		failure := errors.New("close failed")
		processes := make([]*routeProcess, 6)
		for index := range processes {
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			processes[index] = &routeProcess{index: index, cancel: cancel, done: done}
			go func() {
				<-ctx.Done()
				current := active.Add(1)
				for previous := peak.Load(); previous < current; previous = peak.Load() {
					if peak.CompareAndSwap(previous, current) {
						break
					}
				}
				time.Sleep(time.Duration(index+1) * time.Second)
				active.Add(-1)
				err := error(context.Canceled)
				if index == 2 || index == 3 {
					err = errors.Join(context.Canceled, failure)
				}
				done <- err
			}()
		}
		phase, err := stopRoutes(t.Context(), processes, 2, func() { snapshots.Add(1) })
		if !errors.Is(err, failure) || phase.Attempts != 6 || phase.Successes != 4 || phase.Errors != 2 {
			t.Fatalf("shutdown = %+v, %v", phase, err)
		}
		if peak.Load() != 2 || active.Load() != 0 || snapshots.Load() != 1 {
			t.Fatalf("active=%d peak=%d snapshots=%d", active.Load(), peak.Load(), snapshots.Load())
		}
		if phase.Total.Count != 6 || phase.Total.SumMilliseconds != 21000 || phase.DurationMilliseconds != 12000 {
			t.Fatalf("shutdown durations include queue time or hide failed attempts: %+v", phase)
		}
	})
}

func TestStopRoutesDeadlineCancelsRemainingRoutes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		var canceled atomic.Int32
		processes := make([]*routeProcess, 7)
		for index := 1; index < len(processes); index++ {
			processes[index] = &routeProcess{index: index, cancel: func() { canceled.Add(1) }, done: make(chan error)}
		}
		phase, err := stopRoutes(ctx, processes, 2, nil)
		if !errors.Is(err, context.DeadlineExceeded) || phase.Attempts != 6 || phase.Successes != 0 || phase.Errors != 6 || canceled.Load() != 6 || phase.DurationMilliseconds != 1000 {
			t.Fatalf("deadline shutdown = %+v canceled=%d err=%v", phase, canceled.Load(), err)
		}
	})
}

func TestShutdownCapturesFirstFailureBeforeStoppingNextRoute(t *testing.T) {
	var nextCanceled atomic.Bool
	var snapshots, metrics atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if nextCanceled.Load() {
			t.Error("diagnostics collected after starting the next shutdown")
		}
		if r.URL.Path == "/debug/database" {
			snapshots.Add(1)
			_, _ = w.Write([]byte(`{"active_operations":[{"operation":"LockRouteSession","elapsed_seconds":1}]}`))
		} else {
			metrics.Add(1)
			_, _ = w.Write([]byte("tnl_database_pool_acquired_connections 8\n"))
		}
	}))
	defer server.Close()
	failure := &failureCapture{ctx: t.Context(), diagnosticURLs: []string{server.URL + "/debug/database"}, metricsURLs: []string{server.URL + "/metrics#control"}}
	failed, succeeded := make(chan error, 1), make(chan error, 1)
	failed <- errors.New("close deadline exceeded")
	succeeded <- nil
	phase, err := stopRoutes(t.Context(), []*routeProcess{
		{index: 0, cancel: func() {}, done: failed},
		{index: 1, cancel: func() { nextCanceled.Store(true) }, done: succeeded},
	}, 1, failure.capture)
	failure.capture() // The worker's fallback capture must not duplicate evidence.
	if err == nil || phase.Successes != 1 || phase.Errors != 1 || snapshots.Load() != 1 || metrics.Load() != 1 || len(failure.diagnostics) != 1 || len(failure.resources) != 1 {
		t.Fatalf("shutdown evidence lost: phase=%+v snapshots=%d metrics=%d err=%v", phase, snapshots.Load(), metrics.Load(), err)
	}
}
