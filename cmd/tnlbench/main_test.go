package main

import (
	"testing"
	"time"
)

func TestLoadValidationBoundsGeneratorRate(t *testing.T) {
	c := loadCommand{workerCommand: workerCommand{CellID: "target", CoordinatorURL: "http://coordinator.internal:8080", CoordinatorToken: "token", WorkerCount: 1, Timeout: time.Minute}, PublicURLs: 4, FreshRate: 30, HeldStreams: 4, Concurrency: 128, QueueSlots: 8, PayloadBytes: 32768}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.FreshRate = maxBenchmarkFreshRate
	if err := c.Validate(); err != nil {
		t.Fatalf("valid generator rate rejected: %v", err)
	}
	c.FreshRate++
	if c.Validate() == nil {
		t.Fatal("accepted rate above workload maximum")
	}
	c.FreshRate = 30
	c.ResolverAddress = "missing-port"
	if c.Validate() == nil {
		t.Fatal("accepted invalid resolver")
	}
}
