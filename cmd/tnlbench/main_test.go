package main

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestLoadValidationProtectsSourceLimiter(t *testing.T) {
	valid := loadCommand{
		workerCommand: workerCommand{
			CellID: "cell", Suite: "smoke", Repetition: 1, CoordinatorURL: "http://coordinator.internal:8080",
			CoordinatorToken: "secret", WorkerCount: 1,
		},
		Routes: 1, HostnameSuffix: "routes.example.com", TotalFreshRate: 30, TotalHeldStreams: 1,
		FreshRate: 30, HeldStreams: 1, Warmup: 1, Duration: 1,
		PayloadBytes: 1, Timeout: 1,
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	valid.FreshRate = 40
	if err := valid.Validate(); err == nil {
		t.Fatal("source-limiter rate was accepted")
	}
}

func TestCleanupDeletesDurableRoutesAfterPublisherStops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stopped, canceled := make(chan struct{}), make(chan struct{})
		cleaner := &cleanerStub{stopped: stopped, routes: []controlv1.Route{{Id: "route_1", TeamId: "team_1"}}}
		done := make(chan error, 1)
		processes := []*routeProcess{{teamID: "team_1", routeID: "route_1", cancel: func() { close(canceled) }, done: done}}
		finished := make(chan error, 1)
		go func() { _, err := cleanupRoutes(t.Context(), 1, cleaner, processes); finished <- err }()
		synctest.Wait()
		select {
		case <-canceled:
		default:
			t.Error("publisher was not canceled")
		}
		cleaner.mu.Lock()
		if len(cleaner.calls) != 0 {
			t.Errorf("cleanup before publisher stopped: %v", cleaner.calls)
		}
		cleaner.mu.Unlock()
		close(stopped)
		done <- nil
		if err := <-finished; err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(cleaner.deleted, []string{"route_1"}) || !slices.Equal(cleaner.calls, []string{"list:team_1", "delete:route_1", "list:team_1"}) {
			t.Fatalf("deleted = %v, calls = %v", cleaner.deleted, cleaner.calls)
		}
	})
}

type cleanerStub struct {
	mu      sync.Mutex
	routes  []controlv1.Route
	deleted []string
	calls   []string
	stopped <-chan struct{}
}

func (c *cleanerStub) ListRoutes(_ context.Context, team string) ([]controlv1.Route, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, "list:"+team)
	select {
	case <-c.stopped:
	default:
		return nil, fmt.Errorf("list before publisher stopped")
	}
	return append([]controlv1.Route(nil), c.routes...), nil
}

func (c *cleanerStub) DeleteRoute(_ context.Context, routeID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, "delete:"+routeID)
	select {
	case <-c.stopped:
	default:
		return fmt.Errorf("delete before publisher stopped")
	}
	c.deleted = append(c.deleted, routeID)
	c.routes = nil
	return nil
}
