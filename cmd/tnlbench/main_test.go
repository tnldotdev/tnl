package main

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
)

func TestLoadValidationProtectsSourceLimiter(t *testing.T) {
	c := loadCommand{workerCommand: workerCommand{CellID: "target", CoordinatorURL: "http://coordinator.internal:8080", CoordinatorToken: "token", WorkerCount: 1, Timeout: time.Minute}, Routes: 4, FreshRate: 30, HeldStreams: 4, Concurrency: 128, QueueSlots: 8, PayloadBytes: 32768}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.FreshRate = 40
	if c.Validate() == nil {
		t.Fatal("accepted source-limiter rate")
	}
	c.FreshRate = 30
	c.ResolverAddress = "missing-port"
	if c.Validate() == nil {
		t.Fatal("accepted invalid resolver")
	}
}

func TestAssignmentsCoverEachRouteAndPreserveBudgets(t *testing.T) {
	seen := make(map[int]bool)
	workers, queue, rate := 0, 0, 0
	for i := range 6 {
		for _, index := range benchworkload.RouteIndexes(43, 6, i) {
			if seen[index] {
				t.Fatal("duplicate route")
			}
			seen[index] = true
		}
		workers += benchworkload.Assignment(128, 6, i)
		queue += benchworkload.Assignment(8, 6, i)
		rate += benchworkload.Assignment(160, 6, i)
	}
	if len(seen) != 43 || workers != 128 || queue != 8 || rate != 160 {
		t.Fatal("assignments changed workload")
	}
}
