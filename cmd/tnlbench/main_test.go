package main

import (
	"testing"
	"time"
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
