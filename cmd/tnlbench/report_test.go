package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
)

func TestReportMergesBucketsAndDoesNotHideMissingWorkerOrShutdownFailure(t *testing.T) {
	rows := []benchmarkResult{passedTestResult(resultWorker{Kind: "publisher", Count: 1})}
	for i := range 2 {
		row := passedTestResult(resultWorker{Kind: "load", Index: i, Count: 2})
		v := benchworkload.VisitorResult{Workers: 64, QueueSlots: 4, Rate: 8, Scheduled: 10, Started: 10, Completed: 10, Successes: 10, OfferDuration: time.Second}
		for range 10 {
			v.Total.Observe(time.Duration(i+1) * time.Millisecond)
		}
		row.Phases = []phaseResult{{Name: "steady-1", Visitor: &v}}
		rows = append(rows, row)
	}
	r, err := buildReport(rows)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "passed" || r.Phases["steady-1"].Visitor.Total.Count != 20 || r.Phases["steady-1"].Visitor.Workers != 128 {
		t.Fatalf("report=%+v", r)
	}
	rows[0].Status = "failed"
	rows[0].Cleanup.Exact = false
	rows[0].Failure = &resultFailure{Stage: "cleanup", Message: "close failed"}
	r, err = buildReport(rows)
	if err != nil || r.Status != "failed" || r.VisitorStatus != "passed" || r.ShutdownStatus != "failed" {
		t.Fatalf("shutdown report=%+v err=%v", r, err)
	}
	r, err = buildReport(rows[:2])
	if err != nil || !r.Incomplete || r.VisitorStatus != "incomplete" {
		t.Fatalf("missing worker=%+v err=%v", r, err)
	}
}

func TestReportRejectsDuplicateWorkersAndInvalidAccounting(t *testing.T) {
	row := passedTestResult(resultWorker{Kind: "load", Count: 1})
	if _, err := buildReport([]benchmarkResult{row, row}); err == nil {
		t.Fatal("accepted duplicate result")
	}
	row.Phases = []phaseResult{{Name: "steady-1", Visitor: &benchworkload.VisitorResult{Scheduled: 10, Successes: 9}}}
	if _, err := buildReport([]benchmarkResult{row}); err == nil {
		t.Fatal("accepted lost request accounting")
	}
}

func TestReportWritesInterruptedRunAndInfrastructureFailure(t *testing.T) {
	for _, status := range []string{"cleaned", "cleanup_failed"} {
		t.Run(status, func(t *testing.T) {
			dir := t.TempDir()
			plan, err := testWorkload().build()
			if err != nil {
				t.Fatal(err)
			}
			if err := writeIndentedJSON(filepath.Join(dir, "plan.json"), plan); err != nil {
				t.Fatal(err)
			}
			if err := writeIndentedJSON(filepath.Join(dir, "manifest.json"), runManifest{Status: status}); err != nil {
				t.Fatal(err)
			}
			var output strings.Builder
			if err := (reportCommand{RunDirectory: dir, allowIncomplete: true}).run(&output); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(dir, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			var result benchmarkReport
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
			if result.Status != "failed" || !result.Incomplete || result.InfrastructureCleanup != status {
				t.Fatalf("report=%+v", result)
			}
		})
	}
}

func TestServerDurationReportsKeepProcessesAndFailureBoundariesSeparate(t *testing.T) {
	at := time.Now()
	metric := func(count string) string {
		return "# TYPE tnl_operation_duration_seconds histogram\ntnl_operation_duration_seconds_bucket{le=\"1\"} " + count + "\ntnl_operation_duration_seconds_bucket{le=\"+Inf\"} " + count + "\ntnl_operation_duration_seconds_count " + count + "\ntnl_operation_duration_seconds_sum " + count + "\n"
	}
	samples := []resourceSample{{Role: "control", Identity: "a", Moment: "steady-1-before", Timestamp: at, Metrics: metricsForTest(metric("1"))}, {Role: "control", Identity: "a", Moment: "steady-1-after", Timestamp: at.Add(time.Second), Metrics: metricsForTest(metric("3"))}, {Role: "control", Identity: "b", Moment: "steady-1-before", Timestamp: at, Metrics: metricsForTest(metric("100"))}}
	reports := serverDurationReports(samples)
	if len(reports) != 2 || !reports[0].Complete || reports[0].Durations[0].Count != 2 || reports[1].Complete || reports[1].Error == "" {
		t.Fatalf("intervals=%+v", reports)
	}
	samples[1].Metrics = metricsForTest(metric("0"))
	if reports := serverDurationReports(samples); reports[0].Complete {
		t.Fatal("counter reset accepted")
	}
}
