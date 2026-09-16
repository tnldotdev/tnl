package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildReportMergesWorkersAndFindsCapacityBoundaries(t *testing.T) {
	results := []benchmarkResult{
		reportTestResult("confirm-r100-c10-s100-rep1", 0, 1, "publisher", 0, 1, "passed", time.Millisecond),
		reportTestResult("confirm-r100-c10-s100-rep1", 0, 1, "load", 0, 1, "passed", 2*time.Millisecond),
		reportTestResult("confirm-r100-c10-s100-rep2", 0, 2, "publisher", 0, 1, "passed", time.Millisecond),
		reportTestResult("confirm-r100-c10-s100-rep2", 0, 2, "load", 0, 1, "passed", 3*time.Millisecond),
		reportTestResult("confirm-r200-c20-s200-rep1", 1, 1, "publisher", 0, 1, "passed", time.Millisecond),
		reportTestResult("confirm-r200-c20-s200-rep1", 1, 1, "load", 0, 1, "failed", 100*time.Millisecond),
	}
	report, err := buildReport(results)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "failed" || report.HighestRepeatablyPassing == nil || report.HighestRepeatablyPassing.Routes != 100 ||
		report.FirstSaturation == nil || report.FirstSaturation.Routes != 200 {
		t.Fatalf("report = %#v", report)
	}
	if phase := report.Cells[0].Phases["fresh"]; phase.TotalP95 != 2 || phase.Attempts != 2 {
		t.Fatalf("phase = %#v", phase)
	}
}

func TestReportCommandWritesArtifacts(t *testing.T) {
	directory := t.TempDir()
	var rows bytes.Buffer
	for _, result := range []benchmarkResult{
		reportTestResult("smoke-r2-c2-s2-rep1", 0, 1, "publisher", 0, 1, "passed", time.Millisecond),
		reportTestResult("smoke-r2-c2-s2-rep1", 0, 1, "load", 0, 1, "passed", time.Millisecond),
	} {
		if err := json.NewEncoder(&rows).Encode(result); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(directory, "results.jsonl"), rows.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	if err := (reportCommand{RunDirectory: directory}).run(&output); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(directory, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report benchmarkReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != 2 || report.Status != "passed" || len(report.Cells) != 1 || report.Cells[0].ResultRows != 2 {
		t.Fatalf("report = %#v", report)
	}
	markdown, err := os.ReadFile(filepath.Join(directory, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"Status: **passed**", "Highest repeatably passing cell: not established.", "not product SLOs"} {
		if !strings.Contains(string(markdown), fragment) {
			t.Fatalf("report missing %q:\n%s", fragment, markdown)
		}
	}
}

func TestBuildReportMarksMissingWorkerAsFailure(t *testing.T) {
	result := reportTestResult("smoke-r2-c2-s2-rep1", 0, 1, "publisher", 0, 2, "passed", time.Millisecond)
	report, err := buildReport([]benchmarkResult{result})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "failed" || len(report.Cells[0].Failures) != 2 {
		t.Fatalf("report = %#v", report)
	}
}

func reportTestResult(cellID string, sequence, repetition int, kind string, index, count int, status string, sample time.Duration) benchmarkResult {
	result := benchmarkResult{
		SchemaVersion: benchmarkResultSchemaVersion, CellID: cellID, Status: status, Suite: "confirm", Repetition: repetition,
		Worker:        resultWorker{Kind: kind, Index: index, Count: count},
		Configuration: resultConfiguration{Sequence: sequence, Routes: 100, FreshConnectionsPerSecond: 10, HeldStreams: 100},
		Phases:        []phaseResult{{Name: "fresh", Attempts: 1, Successes: 1, Total: newDurationHistogram([]time.Duration{sample})}},
	}
	if strings.Contains(cellID, "r200") {
		result.Configuration.Routes = 200
		result.Configuration.FreshConnectionsPerSecond = 20
		result.Configuration.HeldStreams = 200
	}
	if status == "failed" {
		result.Failure = &resultFailure{Message: "saturated"}
		result.Phases[0].Successes = 0
		result.Phases[0].Errors = 1
	}
	return result
}
