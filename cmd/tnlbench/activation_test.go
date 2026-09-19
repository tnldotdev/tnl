package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher"
)

func TestActivationFailureCapturesBeforeCancelAndStopsLaunching(t *testing.T) {
	running, canceled := make(chan struct{}), make(chan struct{})
	snapshot := false
	failure := errors.New("activation failed")
	flags := publisherCommand{Parallel: 2, NoProgressTimeout: time.Second, onFailure: func() {
		select {
		case <-canceled:
			t.Error("publisher canceled before snapshot")
		default:
		}
		snapshot = true
	}}
	processes, timings, err := activateRoutesWithRunner(t.Context(), flags, nil, "", []benchmarkRouteSpec{
		{index: 0, hostname: "fail"}, {index: 1, hostname: "pending"}, {index: 2, hostname: "never"},
	}, func(ctx context.Context, cfg publisher.Config) error {
		if cfg.Hostname == "fail" {
			<-running
			return failure
		}
		close(running)
		<-ctx.Done()
		close(canceled)
		return ctx.Err()
	})
	defer stopRoutes(t.Context(), processes, flags.Parallel, nil)
	if !errors.Is(err, failure) || !snapshot || processes[2] != nil || len(timings) != 0 {
		t.Fatalf("activation: err=%v snapshot=%t timings=%v processes=%v", err, snapshot, timings, processes)
	}
}

func TestActivationNoProgressPreservesPartialSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := false
		flags := publisherCommand{Parallel: 1, NoProgressTimeout: time.Minute, onFailure: func() { snapshot = true }}
		started := time.Now()
		processes, timings, err := activateRoutesWithRunner(t.Context(), flags, nil, "", []benchmarkRouteSpec{
			{index: 0, hostname: "ready"}, {index: 1, hostname: "stalled"}, {index: 2, hostname: "never"},
		}, func(ctx context.Context, cfg publisher.Config) error {
			if cfg.Hostname == "ready" {
				_ = cfg.Observe(publisher.Event{Type: publisher.EventReady})
			}
			<-ctx.Done()
			return ctx.Err()
		})
		defer stopRoutes(t.Context(), processes, flags.Parallel, nil)
		if err == nil || !strings.Contains(err.Error(), "no progress") || !snapshot || len(timings) != 1 || processes[2] != nil {
			t.Fatalf("activation: err=%v snapshot=%t timings=%v", err, snapshot, timings)
		}
		phase := activationResult("activation", started, processes, timings, err)
		if phase.Attempts != 2 || phase.Successes != 1 || phase.Errors != 1 || time.Since(started) != time.Minute {
			t.Fatalf("partial activation = %+v", phase)
		}
	})
}
