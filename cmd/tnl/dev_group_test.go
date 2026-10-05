package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCoordinateDevStopsEveryServiceWhenOneFails(t *testing.T) {
	started := make(chan string, 2)
	ready := make(chan struct{}, 2)
	failed := make(chan struct{})
	stopped := make(chan string, 2)
	go func() {
		<-ready
		<-ready
		close(failed)
	}()
	err := coordinateDev(t.Context(), []string{"api", "web"}, func(ctx context.Context, name string) error {
		started <- name
		ready <- struct{}{}
		if name == "web" {
			<-failed
			return errors.New("startup failed")
		}
		<-ctx.Done()
		stopped <- name
		return ctx.Err()
	})
	if err == nil || !strings.Contains(err.Error(), `service "web": startup failed`) {
		t.Fatalf("coordinated error = %v", err)
	}
	if len(started) != 2 || <-stopped != "api" {
		t.Fatal("not all configured services started and stopped")
	}
}

func TestCoordinateDevPropagatesCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	cause := errors.New("user interrupted")
	started := make(chan struct{}, 2)
	go func() {
		<-started
		<-started
		cancel(cause)
	}()
	err := coordinateDev(ctx, []string{"api", "web"}, func(ctx context.Context, _ string) error {
		started <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	})
	if !errors.Is(err, cause) {
		t.Fatalf("cancellation cause = %v", err)
	}
}
