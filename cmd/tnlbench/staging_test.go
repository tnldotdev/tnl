package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
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

func TestWaitForPublicURLDNSRetriesUntilAvailable(t *testing.T) {
	attempts := 0
	lookup := func(_ context.Context, hostname string) ([]net.IPAddr, error) {
		if hostname != "example.test" {
			t.Fatalf("unexpected lookup: %s", hostname)
		}
		attempts++
		if attempts == 1 {
			return nil, errors.New("no such host")
		}
		return []net.IPAddr{{IP: net.IPv4(192, 0, 2, 1)}}, nil
	}
	if err := waitForPublicURLDNS(t.Context(), []string{"https://example.test"}, lookup); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("lookups = %d, want retry after first NXDOMAIN", attempts)
	}
}

func TestWaitForPublicURLDNSStopsWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return nil, errors.New("no such host")
	}
	if err := waitForPublicURLDNS(ctx, []string{"https://example.test"}, lookup); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled DNS readiness = %v", err)
	}
}

func TestCanceledRunPersistsResultBeforePublishing(t *testing.T) {
	t.Setenv("BENCH_SUITE", "smoke")
	options := smokeOptions()
	options.ResultsRoot = t.TempDir()
	command := runCommand{workloadOptions: options, Approved: "1"}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var stdout, progress bytes.Buffer
	if err := command.run(ctx, &stdout, &progress); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled run = %v", err)
	}
	path := strings.TrimPrefix(strings.SplitN(stdout.String(), "\n", 2)[0], "Results: ")
	if filepath.Dir(filepath.Dir(path)) != options.ResultsRoot {
		t.Fatalf("result path outside results root: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result benchmarkResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "interrupted" || result.CleanupStatus != "not_needed" || result.CleanupExact || len(result.PublicURLs) != 0 {
		t.Fatalf("canceled result = %+v", result)
	}
	if !strings.Contains(progress.String(), "local baseline stopped") {
		t.Fatalf("missing cancellation progress: %s", progress.String())
	}
}

func TestPhaseReportsProgressWhileRunning(t *testing.T) {
	var progress bytes.Buffer
	if err := reportPhaseEvery(&progress, "local baseline", 80*time.Millisecond, 10*time.Millisecond, func() error {
		return wait(t.Context(), 80*time.Millisecond)
	}); err != nil {
		t.Fatal(err)
	}
	for _, message := range []string{"local baseline started", "local baseline still running", "local baseline complete"} {
		if !strings.Contains(progress.String(), message) {
			t.Fatalf("progress missing %q: %s", message, progress.String())
		}
	}
}
