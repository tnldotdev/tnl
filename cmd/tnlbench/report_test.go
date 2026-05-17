package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildReportMergesShardHistograms(t *testing.T) {
	results := []benchmarkResult{
		reportTestResult(0, []time.Duration{time.Millisecond, 2 * time.Millisecond}),
		reportTestResult(1, []time.Duration{100 * time.Millisecond, 200 * time.Millisecond}),
	}
	report, err := buildReport(results)
	if err != nil {
		t.Fatal(err)
	}
	phase := report.Cells[0].Phases["correctness"]
	if report.Status != "passed" || report.PassedRows != 2 || phase.LatencyP50Millis != 2 ||
		phase.LatencyP95Millis != 200 {
		t.Fatalf("report = %#v", report)
	}
}

func TestReportCommandWritesArtifacts(t *testing.T) {
	directory := t.TempDir()
	row, err := json.Marshal(reportTestResult(0, []time.Duration{time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "results.jsonl"), append(row, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	if err := (reportCommand{RunDirectory: directory}).run(&output); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"report.json", "report.md"} {
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func reportTestResult(shard int, samples []time.Duration) benchmarkResult {
	return benchmarkResult{
		SchemaVersion: 2, CellID: "smoke-w1-r25-rep1", Status: "passed", Suite: "smoke",
		Workload: "agent-worktrees-assumed-v1", Repetition: 1, Shard: resultShard{Index: shard, Count: 2},
		Phases: []phaseResult{{
			Name: "correctness", Attempts: len(samples), Successes: len(samples), Latency: newDurationHistogram(samples),
		}},
	}
}
