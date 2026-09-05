package main

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
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
	if phase := report.Cells[0].Phases["fresh"]; phase.TotalP95 == nil || math.Abs(*phase.TotalP95-2.35) > 1e-9 || phase.Attempts != 2 {
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
	if err := saveManifest(filepath.Join(directory, "manifest.json"), &runManifest{Status: "cleaned"}); err != nil {
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
	if report.SchemaVersion != 4 || report.Status != "passed" || report.InfrastructureCleanup != "passed" || report.ProfileID != "production-test" ||
		len(report.Cells) != 1 || report.Cells[0].ResultRows != 2 || report.Cells[0].MonthlyCostUSD != 100 ||
		report.Cells[0].CapacityPerDollar != 1 {
		t.Fatalf("report = %#v", report)
	}
	markdown, err := os.ReadFile(filepath.Join(directory, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"Status: **passed**", "Infrastructure cleanup: **passed**", "Highest repeatably passing cell: not established.", "not product SLOs"} {
		if !strings.Contains(string(markdown), fragment) {
			t.Fatalf("report missing %q:\n%s", fragment, markdown)
		}
	}
}

func TestReportKeepsVisitorSuccessWhenShutdownFails(t *testing.T) {
	for _, legacyCounts := range []bool{false, true} {
		publisher := reportTestResult("cell", 0, 1, "publisher", 0, 1, "passed", time.Millisecond)
		publisher.Status = "failed"
		publisher.Failure = &resultFailure{Message: "close deadline exceeded", Stage: "cleanup"}
		publisher.Phases = []phaseResult{{Name: "deactivation", Attempts: 100, Successes: 99, Errors: 1}}
		if legacyCounts {
			publisher.Phases[0].Successes, publisher.Phases[0].Errors = 100, 0
		}
		load := reportTestResult("cell", 0, 1, "load", 0, 1, "passed", time.Millisecond)
		report, err := buildReport([]benchmarkResult{publisher, load})
		if err != nil {
			t.Fatal(err)
		}
		cell := report.Cells[0]
		if report.Status != "failed" || cell.VisitorStatus != "passed" || cell.ShutdownStatus != "failed" || cell.FailureStage != "cleanup" || report.HighestPassing != nil || report.FirstSaturation != nil {
			t.Fatalf("cleanup failure changed workload outcome or capacity: %+v", report)
		}
		if text := formatReportMarkdown(report); !strings.Contains(text, "Visitor workload: **passed**. Route-session shutdown: **failed**.") {
			t.Fatalf("phase outcomes missing: %s", text)
		}
	}
}

func TestReportDoesNotCallMissingWorkersSuccessful(t *testing.T) {
	load := reportTestResult("cell", 0, 1, "load", 0, 2, "passed", time.Millisecond)
	publisher := reportTestResult("cell", 0, 1, "publisher", 0, 2, "passed", time.Millisecond)
	publisher.Phases = []phaseResult{{Name: "deactivation", Attempts: 1, Successes: 1}}
	report, err := buildReport([]benchmarkResult{publisher, load})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "failed" || report.Cells[0].VisitorStatus != "incomplete" || report.Cells[0].ShutdownStatus != "incomplete" {
		t.Fatalf("missing workers reported as successful: %+v", report)
	}
}

func TestReportRecordsInfrastructureCleanupFailure(t *testing.T) {
	directory := t.TempDir()
	if err := saveManifest(filepath.Join(directory, "manifest.json"), &runManifest{Status: "cleanup_failed"}); err != nil {
		t.Fatal(err)
	}
	if err := (reportCommand{RunDirectory: directory, allowIncomplete: true}).run(&bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var report benchmarkReport
	if err := decodeJSONFile(filepath.Join(directory, "report.json"), &report); err != nil {
		t.Fatal(err)
	}
	if report.InfrastructureCleanup != "failed" || report.Status != "failed" {
		t.Fatalf("cleanup failure lost: %+v", report)
	}
}

func TestReportCommandWritesEmptyFailureReportForInterruptedRun(t *testing.T) {
	directory := t.TempDir()
	plan := benchmarkPlan{SchemaVersion: 3, ProfileID: "production-test", Region: "sjc", Suite: "smoke"}
	planData, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "plan.json"), planData, 0o600); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	if err := (reportCommand{RunDirectory: directory, allowIncomplete: true}).run(&output); err != nil {
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
	if report.Status != "failed" || !report.Incomplete || report.ResultRows != 0 || len(report.Cells) != 0 || report.ProfileID != plan.ProfileID {
		t.Fatalf("report = %#v", report)
	}
	markdown, err := os.ReadFile(filepath.Join(directory, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(markdown), "ended before all planned cells produced results") {
		t.Fatalf("markdown = %s", markdown)
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
		{Role: "ingress", Identity: "ingress-1", Moment: "ready", Timestamp: started, Metrics: metricsForTest(
			"tnl_source_limiter_rejections_total 0\nprocess_cpu_seconds_total 10\n# TYPE tnl_capacity_rejections_total counter\n" + capacityMetric + " 0\n",
		)},
		{Role: "ingress", Identity: "ingress-1", Moment: "load-000001", Timestamp: started.Add(time.Second), Metrics: metricsForTest(
			"process_cpu_seconds_total 11.5\n",
		)},
		{Role: "ingress", Identity: "ingress-1", Moment: "load-000002", Timestamp: started.Add(1500 * time.Millisecond), Error: "temporary scrape failure"},
		{Role: "ingress", Identity: "ingress-1", Moment: "loaded", Timestamp: started.Add(2 * time.Second), Metrics: metricsForTest(
			"tnl_source_limiter_rejections_total 0\nprocess_cpu_seconds_total 12\n# TYPE tnl_capacity_rejections_total counter\n" + capacityMetric + " 3\n",
		)},
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
	results[0].Resources[1].Metrics = metricsForTest("tnl_source_limiter_rejections_total 3\n")
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
			{Role: "ingress", Identity: "ingress-1", Moment: "ready", Metrics: metricsForTest("tnl_source_limiter_rejections_total 0\n")},
			{Role: "ingress", Identity: "ingress-1", Moment: "loaded", Metrics: metricsForTest("tnl_source_limiter_rejections_total 0\n")},
		}
	}
	return result
}

func TestServerDurationReportsKeepProcessesSeparate(t *testing.T) {
	var samples []resourceSample
	for index, identity := range []string{"control-1", "control-2"} {
		metrics := observability.New("control")
		metrics.ObserveOperation("CreateRouteSession", nil, time.Second)
		before, err := metrics.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for range index + 1 {
			metrics.ObserveOperation("CreateRouteSession", nil, time.Duration(index+1)*time.Millisecond)
		}
		after, err := metrics.Gather()
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		samples = append(samples,
			resourceSample{Role: "control", Identity: identity, Moment: "ready", Timestamp: started, Metrics: before},
			resourceSample{Role: "control", Identity: identity, Moment: "loaded", Timestamp: started.Add(time.Second), Metrics: after},
		)
	}
	reports := serverDurationReports(samples)
	if len(reports) != 2 || reports[0].Identity != "control-1" || reports[1].Identity != "control-2" {
		t.Fatalf("processes pooled: %+v", reports)
	}
	for index, report := range reports {
		if !report.Complete || len(report.Durations) != 1 || report.Durations[0].Count != uint64(index+1) {
			t.Fatalf("process delta lost: %+v", report)
		}
	}
}

func TestServerDurationReportsIncompleteIntervals(t *testing.T) {
	metrics := observability.New("control")
	metrics.ObserveOperation("RenewIngress", nil, time.Millisecond)
	baseline, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	metrics.ObserveOperation("RenewIngress", nil, time.Millisecond)
	final, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	before := resourceSample{Role: "control", Identity: "control-1", Moment: "ready", Timestamp: started, Metrics: baseline}
	after := resourceSample{Role: "control", Identity: "control-1", Moment: "loaded", Timestamp: started.Add(time.Second), Metrics: final}
	for _, name := range []string{"missing baseline", "missing final", "scrape error", "reset", "first failure", "duplicate", "empty scrape"} {
		t.Run(name, func(t *testing.T) {
			samples := []resourceSample{before, after}
			switch name {
			case "missing baseline":
				samples = samples[1:]
			case "missing final":
				samples = samples[:1]
			case "scrape error":
				samples[1].Error = "HTTP 503"
			case "reset":
				samples[0].Metrics, samples[1].Metrics = final, baseline
			case "first failure":
				samples[1].Moment = "failure"
			case "duplicate":
				samples = append(samples, before)
			case "empty scrape":
				samples[1].Metrics = nil
			}
			reports := serverDurationReports(samples)
			if len(reports) != 1 || reports[0].Complete || reports[0].Error == "" {
				t.Fatalf("invalid interval reported complete: %+v", reports)
			}
			if name == "first failure" {
				if len(reports[0].Durations) != 1 || reports[0].Durations[0].Count != 1 {
					t.Fatalf("failure interval lost partial measurements: %+v", reports)
				}
			} else if len(reports[0].Durations) != 0 {
				t.Fatalf("invalid interval fabricated observations: %+v", reports)
			}
			if text := formatReportMarkdown(benchmarkReport{Cells: []cellReport{{ServerDurations: reports}}}); !strings.Contains(text, "Metrics unavailable or incomplete:") {
				t.Fatalf("missing data hidden in markdown: %s", text)
			}
		})
	}
}

func TestServerDurationReportsEmptyIntervalDoesNotInventLatency(t *testing.T) {
	metrics := observability.New("control")
	metrics.ObserveOperation("RenewIngress", nil, time.Millisecond)
	baseline, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	reports := serverDurationReports([]resourceSample{
		{Role: "control", Identity: "control-1", Moment: "ready", Timestamp: started, Metrics: baseline},
		{Role: "control", Identity: "control-1", Moment: "loaded", Timestamp: started.Add(time.Second), Metrics: baseline},
	})
	if len(reports) != 1 || !reports[0].Complete || len(reports[0].Durations) != 1 || reports[0].Durations[0].Count != 0 || reports[0].Durations[0].P95Seconds != nil {
		t.Fatalf("empty interval fabricated latency: %+v", reports)
	}
	text := formatReportMarkdown(benchmarkReport{Cells: []cellReport{{ServerDurations: reports}}})
	if !strings.Contains(text, "| 0 | 0.000000 | n/a | n/a | n/a | n/a |") {
		t.Fatalf("empty observations displayed as success: %s", text)
	}
}
