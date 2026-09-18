package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
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
		report.FirstSaturation == nil || report.FirstSaturation.Routes != 200 || len(report.CapacityRamps) != 1 ||
		report.CapacityRamps[0].LastRepeatablyPassing == nil || report.CapacityRamps[0].FirstFailing == nil {
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
	plan := benchmarkPlan{
		SchemaVersion: 3, ProfileID: "production-test", Suite: "confirm", Region: "sjc",
		CertificateAuthority: benchmarkCertificateAuthorityPebble,
		Topology:             benchmarkTopology{ControlProcesses: 2, IngressProcesses: 2, RelayServices: 2, RelayProcessesPerService: 2},
		ExpectedSpendUSD:     1.25, MaximumSpendUSD: 5,
		Cells: []planCell{{
			ID: "smoke-r2-c2-s2-rep1", Axis: "confirm", Repetition: 1, Routes: 100,
			FreshConnectionsPerSecond: 10, HeldStreams: 100, PayloadBytes: 16 << 10, EstimatedMonthlyCostUSD: 100,
		}},
	}
	planData, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "plan.json"), planData, 0o600); err != nil {
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
	if report.SchemaVersion != 3 || report.Status != "passed" || report.ProfileID != "production-test" ||
		len(report.Cells) != 1 || report.Cells[0].ResultRows != 2 || report.Cells[0].MonthlyCostUSD != 100 ||
		report.Cells[0].CapacityPerDollar != 1 {
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

func TestBuildReportRecordsRecoveryAndCapacityEvidence(t *testing.T) {
	results := []benchmarkResult{
		reportTestResult("confirm-r100-c10-s100-rep1", 0, 1, "publisher", 0, 1, "passed", time.Millisecond),
		reportTestResult("confirm-r100-c10-s100-rep1", 0, 1, "load", 0, 1, "failed", time.Millisecond),
	}
	started := time.Now().UTC()
	capacityMetric := `tnl_capacity_rejections_total{resource="route_connections"}`
	results[0].Resources = []resourceSample{
		{Role: "ingress", Identity: "ingress-1", Moment: "ready", Timestamp: started, Metrics: map[string]float64{
			"tnl_source_limiter_rejections_total": 0, "process_cpu_seconds_total": 10, capacityMetric: 0,
		}},
		{Role: "ingress", Identity: "ingress-1", Moment: "load-000001", Timestamp: started.Add(time.Second), Metrics: map[string]float64{
			"process_cpu_seconds_total": 11.5,
		}},
		{Role: "ingress", Identity: "ingress-1", Moment: "load-000002", Timestamp: started.Add(1500 * time.Millisecond), Error: "temporary scrape failure"},
		{Role: "ingress", Identity: "ingress-1", Moment: "loaded", Timestamp: started.Add(2 * time.Second), Metrics: map[string]float64{
			"tnl_source_limiter_rejections_total": 0, "process_cpu_seconds_total": 12, capacityMetric: 3,
		}},
	}
	results[1].Phases = append(results[1].Phases, phaseResult{
		Name: "recovery", DurationMilliseconds: 1500, Attempts: 2, Successes: 1, Errors: 1,
	})
	report, err := buildReport(results)
	if err != nil {
		t.Fatal(err)
	}
	cell := report.Cells[0]
	if cell.Bottleneck != "ingress route connections capacity" || cell.Recovery == nil ||
		cell.Recovery.Workers != 1 || cell.Recovery.RecoveredWorkers != 1 || cell.Recovery.DurationMilliseconds != 1500 ||
		cell.ResourceMaximums["ingress/process_cpu_cores"] != 1.5 ||
		!slices.Contains(cell.BottleneckEvidence, "ingress route_connections capacity rejections increased by 3") {
		t.Fatalf("cell = %#v", cell)
	}
	markdown := formatReportMarkdown(report)
	for _, fragment := range []string{"1500 ms (1/1)", "ingress route connections capacity", "peak ingress was 1.50 cores"} {
		if !strings.Contains(markdown, fragment) {
			t.Fatalf("report missing %q:\n%s", fragment, markdown)
		}
	}
}

func TestCapacityRampsRemainIndependent(t *testing.T) {
	ramps := capacityRamps([]cellReport{
		{Target: "routes-100", Axis: "active_routes", Sequence: 0, Status: "passed", Routes: 100},
		{Target: "routes-200", Axis: "active_routes", Sequence: 1, Status: "failed", Routes: 200},
		{Target: "fresh-20", Axis: "fresh_connections", Sequence: 2, Status: "passed", FreshRate: 20},
		{Target: "fresh-40", Axis: "fresh_connections", Sequence: 3, Status: "failed", FreshRate: 40},
	})
	if len(ramps) != 2 || ramps[0].Axis != "active_routes" || ramps[0].LastPassing.Routes != 100 ||
		ramps[0].FirstFailing.Routes != 200 || ramps[1].Axis != "fresh_connections" ||
		ramps[1].LastPassing.FreshRate != 20 || ramps[1].FirstFailing.FreshRate != 40 {
		t.Fatalf("ramps = %#v", ramps)
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

func TestBuildReportMarksSourceLimiterRejectionsAsFailure(t *testing.T) {
	results := []benchmarkResult{
		reportTestResult("smoke-r2-c2-s2-rep1", 0, 1, "publisher", 0, 1, "passed", time.Millisecond),
		reportTestResult("smoke-r2-c2-s2-rep1", 0, 1, "load", 0, 1, "passed", time.Millisecond),
	}
	results[0].Resources[1].Metrics["tnl_source_limiter_rejections_total"] = 3
	report, err := buildReport(results)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "failed" || report.Cells[0].Status != "failed" ||
		!slices.Contains(report.Cells[0].Failures, "ingress source limiter rejected 3 visitor connections") {
		t.Fatalf("report = %#v", report)
	}
}

func reportTestResult(cellID string, sequence, repetition int, kind string, index, count int, status string, sample time.Duration) benchmarkResult {
	result := benchmarkResult{
		SchemaVersion: benchmarkResultSchemaVersion, CellID: cellID, Status: status, Suite: "confirm", Repetition: repetition,
		Worker: resultWorker{Kind: kind, Index: index, Count: count},
		Configuration: resultConfiguration{
			Axis: "confirm", Sequence: sequence, Routes: 100,
			FreshConnectionsPerSecond: 10, HeldStreams: 100, PayloadBytes: 16 << 10,
		},
		Phases: []phaseResult{{
			Name: "fresh", DurationMilliseconds: 1000, Attempts: 1, Successes: 1, Bytes: 16 << 10,
			Total: newDurationHistogram([]time.Duration{sample}),
		}},
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
	if kind == "publisher" && index == 0 {
		result.Resources = []resourceSample{
			{Role: "ingress", Identity: "ingress-1", Moment: "ready", Metrics: map[string]float64{"tnl_source_limiter_rejections_total": 0}},
			{Role: "ingress", Identity: "ingress-1", Moment: "loaded", Metrics: map[string]float64{"tnl_source_limiter_rejections_total": 0}},
		}
	}
	return result
}
