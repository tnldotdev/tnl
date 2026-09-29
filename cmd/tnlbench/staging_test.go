package main

import (
	"strings"
	"testing"
	"time"
)

func smokeOptions() workloadOptions {
	return workloadOptions{Suite: "smoke", Server: stagingServer, PublicURLs: 4, FreshRate: 16,
		HeldStreams: 4, Concurrency: 128, QueueSlots: 8, PayloadBytes: 32768,
		Repetitions: 1, Warmup: 5 * time.Second, Duration: 10 * time.Second}
}

func TestStagingPlanAndExecutionGate(t *testing.T) {
	options := smokeOptions()
	plan, err := options.plan()
	if err != nil || !plan.ReadOnly || plan.Server != stagingServer {
		t.Fatalf("unexpected staging plan: %+v, %v", plan, err)
	}
	options.Server = "https://control.tnl.dev"
	if _, err := options.plan(); err == nil || !strings.Contains(err.Error(), "staging benchmarks require") {
		t.Fatalf("production server accepted: %v", err)
	}
	options = smokeOptions()
	options.PublicURLs = 5
	if _, err := options.plan(); err == nil {
		t.Fatal("smoke accepted an oversized workload")
	}
	options = smokeOptions()
	if _, err := (runCommand{workloadOptions: options}).validate(); err == nil || !strings.Contains(err.Error(), "BENCH_APPROVED") {
		t.Fatalf("execution without approval accepted: %v", err)
	}
	t.Setenv("BENCH_SUITE", "")
	if _, err := (runCommand{workloadOptions: options, Approved: "1"}).validate(); err == nil || !strings.Contains(err.Error(), "BENCH_SUITE") {
		t.Fatalf("execution without explicit suite accepted: %v", err)
	}
}
