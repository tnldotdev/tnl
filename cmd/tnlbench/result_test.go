package main

import (
	"testing"
	"time"
)

func TestDurationHistogramMergesBeforePercentiles(t *testing.T) {
	left := newDurationHistogram([]time.Duration{time.Millisecond, 2 * time.Millisecond})
	right := newDurationHistogram([]time.Duration{100 * time.Millisecond, 200 * time.Millisecond})
	if err := mergeDurationHistogram(&left, right); err != nil {
		t.Fatal(err)
	}
	if left.Count != 4 || left.SumMilliseconds != 303 || histogramPercentile(left, 50) != 2 ||
		histogramPercentile(left, 95) != 200 || left.MaximumMilliseconds != 200 {
		t.Fatalf("merged histogram = %#v", left)
	}
}

func TestNewBenchmarkResultEmitsFailureRow(t *testing.T) {
	result := newBenchmarkResult(cli{
		CellID: "smoke-relay2-r25-rep1", Suite: "smoke", Workload: "agent-worktrees-assumed-v1",
		Repetition: 1, DriverCount: 1, Routes: 25, Topology: "split",
	}, time.Now().Add(-time.Second), measurements{}, contextErrorForTest{})
	if result.SchemaVersion != 4 || result.Status != "failed" || result.Failure == nil ||
		len(result.Phases) != 1 || result.Phases[0].Errors != 1 || result.Configuration.Topology != "split" {
		t.Fatalf("failure result = %#v", result)
	}
}

type contextErrorForTest struct{}

func (contextErrorForTest) Error() string { return "test failure" }
