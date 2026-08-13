package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSetupFailureCollectsPartialResultsAndStopsCampaign(t *testing.T) {
	state := newCoordinatorState("broken", 2, 1, 250)
	server := httptest.NewServer(coordinatorHandler("secret", state))
	defer server.Close()
	client, err := newCoordinatorClient(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	result := failedResult("broken", "scout", 1, resultWorker{Kind: "publisher", Count: 2},
		resultConfiguration{Axis: "active_routes", Routes: 250, PayloadBytes: 16}, time.Now(), errors.New("activation stalled"))
	if err := client.postResult(t.Context(), result); err != nil {
		t.Fatal(err)
	}
	manifest := &runManifest{}
	var ran []string
	failed, err := executeCampaignCells(newBenchmarkProgress(io.Discard), []planCell{{ID: "broken"}, {ID: "never"}},
		filepath.Join(t.TempDir(), "manifest.json"), manifest, func(cell planCell) (string, int, error) {
			ran = append(ran, cell.ID)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			status, waitErr := waitCell(ctx, newBenchmarkProgress(io.Discard), client, time.Minute)
			if waitErr == nil || !status.AbortCampaign {
				t.Fatalf("wait status=%+v err=%v", status, waitErr)
			}
			data, err := coordinatorResults(ctx, client, status.AbortCampaign)
			if err != nil {
				t.Fatal(err)
			}
			_, rows, err := summarizeCellResults(data)
			if err != nil || rows != 1 {
				t.Fatalf("partial rows=%d err=%v", rows, err)
			}
			return "failed", rows, cellContinuationError(data)
		})
	if !failed || err == nil || len(ran) != 1 || len(manifest.Cells) != 1 || manifest.Cells[0].ResultRows != 1 {
		t.Fatalf("campaign failed=%t err=%v ran=%v manifest=%+v", failed, err, ran, manifest)
	}
}

func TestMeasuredSaturationRequiresRecoveryBeforeContinuing(t *testing.T) {
	for _, recovered := range []bool{false, true} {
		t.Run(map[bool]string{false: "unrecovered", true: "recovered"}[recovered], func(t *testing.T) {
			result := reportTestResult("cell", 0, 1, "load", 0, 1, "failed", time.Millisecond)
			if recovered {
				result.Phases = append(result.Phases, phaseResult{Name: "recovery", Successes: 1})
			}
			data, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			manifest := &runManifest{}
			calls := 0
			_, err = executeCampaignCells(newBenchmarkProgress(io.Discard), []planCell{{ID: "first"}, {ID: "next"}},
				filepath.Join(t.TempDir(), "manifest.json"), manifest, func(planCell) (string, int, error) {
					calls++
					return "failed", 1, cellContinuationError(data)
				})
			if recovered && (calls != 2 || err != nil) || !recovered && (calls != 1 || err == nil) {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestSetupFailureIsNotReportedAsSaturation(t *testing.T) {
	result := reportTestResult("cell", 0, 1, "publisher", 0, 1, "failed", time.Millisecond)
	result.Failure.Stage = "setup"
	report, err := buildReport([]benchmarkResult{result})
	if err != nil {
		t.Fatal(err)
	}
	if report.FirstSaturation != nil || len(report.Cells) != 1 || report.Cells[0].Bottleneck != "setup failure" {
		t.Fatalf("report=%+v", report)
	}
	if strings.Contains(formatReportMarkdown(report), "First failing target: **") {
		t.Fatal("setup failure established a saturation boundary")
	}
}
