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

func TestFailedResultEmitsWorkerRow(t *testing.T) {
	worker := resultWorker{Kind: "load", Index: 1, Count: 2}
	configuration := resultConfiguration{Sequence: 1, Routes: 25}
	result := failedResult(
		"smoke-r25-c5-s25-rep1", "smoke", 1, worker, configuration,
		time.Now().Add(-time.Second), contextErrorForTest{},
	)
	if result.SchemaVersion != benchmarkResultSchemaVersion || result.Status != "failed" || result.Failure == nil ||
		len(result.Phases) != 1 || result.Phases[0].Errors != 1 || result.Worker != worker || result.Configuration != configuration {
		t.Fatalf("failure result = %#v", result)
	}
}

type contextErrorForTest struct{}

func (contextErrorForTest) Error() string { return "test failure" }
