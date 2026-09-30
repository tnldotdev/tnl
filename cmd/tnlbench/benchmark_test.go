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
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
	"github.com/tnldotdev/tnl/internal/publisher"
)

func smokeOptions() workloadOptions {
	return workloadOptions{Suite: "smoke", Server: "https://control.example.test", Transport: "mixed", VisitorNetwork: "tcp", PublicURLs: 4, FreshRate: 16,
		HeldStreams: 4, Concurrency: 128, QueueSlots: 8, PayloadBytes: 32768,
		Repetitions: 1, Warmup: 5 * time.Second, Duration: 10 * time.Second}
}

func TestBenchmarkPlanAndExecutionGate(t *testing.T) {
	options := smokeOptions()
	plan, err := options.plan()
	if err != nil || !plan.ReadOnly || plan.Server != options.Server || plan.Workload.Transport != "mixed" || plan.Workload.VisitorNetwork != "tcp" {
		t.Fatalf("unexpected benchmark plan: %+v, %v", plan, err)
	}
	options.VisitorNetwork = "tcp4"
	if plan, err := options.plan(); err != nil || plan.Workload.VisitorNetwork != "tcp4" {
		t.Fatalf("IPv4 visitor plan = %+v, %v", plan, err)
	}
	options.VisitorInterface = "missing-tnl-benchmark-interface"
	if _, err := options.plan(); err == nil {
		t.Fatal("accepted a missing visitor interface")
	}
	options.VisitorNetwork = "tcp6"
	if _, err := options.plan(); err == nil || !strings.Contains(err.Error(), "requires IPv4") {
		t.Fatalf("accepted IPv6 with an IPv4 visitor interface: %v", err)
	}
	options = smokeOptions()
	options.Transport = "quic"
	if _, err := options.plan(); err == nil {
		t.Fatal("smoke accepted a changed publisher transport")
	}
	options.Suite = "target"
	if plan, err := options.plan(); err != nil || plan.Workload.Transport != "quic" {
		t.Fatalf("target QUIC plan = %+v, %v", plan, err)
	}
	options.Transport = "auto"
	if plan, err := options.plan(); err != nil || plan.Workload.Transport != "auto" {
		t.Fatalf("target auto plan = %+v, %v", plan, err)
	}
	options.QUICDisablePathMTUDiscovery = true
	if plan, err := options.plan(); err != nil || !plan.Workload.QUICDisablePathMTUDiscovery {
		t.Fatalf("target QUIC path-MTU plan = %+v, %v", plan, err)
	}
	options.QUICQlog = true
	if plan, err := options.plan(); err != nil || !plan.Workload.QUICQlog {
		t.Fatalf("target QUIC qlog plan = %+v, %v", plan, err)
	}
	options.QUICKeepAlive = 5 * time.Second
	if plan, err := options.plan(); err != nil || plan.Workload.QUICKeepAlive != 5*time.Second {
		t.Fatalf("target QUIC keepalive plan = %+v, %v", plan, err)
	}
	options.QUICKeepAlive = 500 * time.Millisecond
	if _, err := options.plan(); err == nil {
		t.Fatal("accepted subsecond QUIC keepalive")
	}
	options = smokeOptions()
	options.Server = "https://control.tnl.dev/"
	if plan, err := options.plan(); err != nil || plan.Server != "https://control.tnl.dev" {
		t.Fatalf("other deployment plan = %+v, %v", plan, err)
	}
	options.Server = "http://control.example.test"
	if _, err := options.plan(); err == nil {
		t.Fatal("accepted an insecure control URL")
	}
	options.Server = ""
	if _, err := options.plan(); err == nil {
		t.Fatal("accepted a missing control URL")
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

func TestAutoTransportReportsFallbacksWithoutMislabelingPublicURLs(t *testing.T) {
	recorder := &transportFallbackRecorder{}
	var group sync.WaitGroup
	for _, id := range []string{"public_url_a", "public_url_b"} {
		group.Go(func() {
			if err := recorder.Observe(0, publisher.Event{Type: publisher.EventTransportFallback, PublicURLID: id}); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if err := recorder.Observe(0, publisher.Event{Type: publisher.EventReady, PublicURLID: "public_url_c"}); err != nil {
		t.Fatal(err)
	}
	events := recorder.Snapshot()
	if len(events) != 2 || events[0].At.IsZero() || events[1].At.IsZero() {
		t.Fatalf("fallback events = %+v", events)
	}
	result := benchmarkResult{RunID: "run-1", Status: "passed", Plan: benchmarkPlan{Workload: workloadSummary{Transport: "auto"}},
		PublicURLInfo: []benchmarkPublicURL{{PublicURL: "https://example.test", PublicURLID: "public_url_a", Transport: "auto"}}, Fallbacks: events,
		Steady:      []benchworkload.VisitorResult{{Scheduled: 1, Successes: 1}},
		SteadyByURL: []map[string]*urlVisitorResult{{"https://example.test": {Scheduled: 1, Successes: 1}}}}
	var output bytes.Buffer
	if err := printResult(&output, result); err != nil || !strings.Contains(output.String(), "public_url_a auto: 1/1 successful") || !strings.Contains(output.String(), "auto: 2 TLS/TCP selection events") {
		t.Fatalf("auto report = %q, %v", output.String(), err)
	}
}

func TestFailedActivationKeepsReadyPublicURLsAndBoundedPublisherErrors(t *testing.T) {
	ready := []benchworkload.PublishedPublicURL{
		{Index: 3, Ready: publisher.Event{PublicURL: "https://third.example", PublicURLID: "public_url_3"}},
		{Index: 1, Ready: publisher.Event{PublicURL: "https://first.example", PublicURLID: "public_url_1"}},
	}
	var result benchmarkResult
	urls := recordReadyPublicURLs(&result, ready, "mixed", 4)
	if len(result.PublicURLs) != 2 || result.PublicURLs[0] != urls[1] || result.PublicURLs[1] != urls[3] ||
		urls[0] != "" || urls[2] != "" || result.PublicURLInfo[0].Index != 1 || result.PublicURLInfo[0].Transport != "tls-tcp" {
		t.Fatalf("partial activation lost ready URLs: %+v, urls=%v", result.PublicURLInfo, urls)
	}
	recorder := &publisherObservationRecorder{}
	if err := recorder.Observe(0, publisher.Event{Type: publisher.EventProvisioning, PublicURLID: "public_url_0"}); err != nil {
		t.Fatal(err)
	}
	for range maxPublisherObservations {
		recorder.Report(0, errors.New("QUIC timeout"))
	}
	observed, dropped := recorder.Snapshot()
	if len(observed) != maxPublisherObservations || dropped != 1 || observed[0].PublicURLID != "public_url_0" || observed[len(observed)-1].Detail != "QUIC timeout" {
		t.Fatalf("publisher diagnostics: count=%d dropped=%d latest=%+v", len(observed), dropped, observed[len(observed)-1])
	}
}

func TestVisitorSourceAddressUsesNamedLocalInterface(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, interface_ := range interfaces {
		if interface_.Flags&net.FlagLoopback == 0 {
			continue
		}
		address, err := visitorSourceAddress(interface_.Name)
		if err == nil && address.IP.IsLoopback() && address.IP.To4() != nil {
			return
		}
	}
	t.Skip("no IPv4 loopback interface available")
}

func TestReportReadsExistingAndGenericBenchmarkResults(t *testing.T) {
	for _, test := range []struct {
		name    string
		version int
		server  string
	}{
		{name: "existing staging", version: 1, server: "https://control.tnl.wtf"},
		{name: "selected deployment", version: 2, server: "https://control.example.test"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			result := benchmarkResult{
				SchemaVersion: test.version, RunID: "run-1", Plan: benchmarkPlan{Server: test.server}, Status: "passed",
			}
			if test.version == 2 {
				result.PublicURLInfo = []benchmarkPublicURL{{PublicURL: "https://example.test", PublicURLID: "public_url_1", Transport: "quic"}}
				result.Steady = []benchworkload.VisitorResult{{Scheduled: 4, Successes: 1}}
				result.SteadyByURL = []map[string]*urlVisitorResult{{"https://example.test": {Scheduled: 4, Successes: 1, Missed: 3}}}
			}
			if err := writeJSON(filepath.Join(dir, "result.json"), result); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if err := (reportCommand{RunDirectory: dir}).run(&output); err != nil || !strings.Contains(output.String(), "run-1: passed") {
				t.Fatalf("report = %q, %v", output.String(), err)
			}
			if test.version == 2 && !strings.Contains(output.String(), "public_url_1 quic: 1/4 successful; 3 missed") {
				t.Fatalf("missing per-URL report: %s", output.String())
			}
		})
	}
}

func TestURLVisitorResultsIdentifyFailuresAndMissedOffers(t *testing.T) {
	urls := []string{"https://a.example", "https://b.example"}
	byURL, observe := newURLVisitorResults(urls)
	observe(benchworkload.RequestResult{URL: urls[0]})
	observe(benchworkload.RequestResult{URL: urls[0], Error: "deadline exceeded", Timeout: true})
	observe(benchworkload.RequestResult{URL: urls[1], Error: "stream reset"})
	observe(benchworkload.RequestResult{URL: urls[1], Error: "queue expired", QueueExpired: true})
	if err := completeURLVisitorResults(urls, 7, byURL); err != nil {
		t.Fatal(err)
	}
	a, b := byURL[urls[0]], byURL[urls[1]]
	if a.Scheduled != 4 || a.Started != 2 || a.Successes != 1 || a.Failures != 1 || a.Timeouts != 1 || a.Missed != 2 || a.FirstFailure == nil || a.FirstFailure.Error != "deadline exceeded" {
		t.Fatalf("first URL = %+v", a)
	}
	if b.Scheduled != 3 || b.Started != 1 || b.Failures != 1 || b.QueueExpired != 1 || b.Missed != 1 || b.FirstFailure == nil || b.FirstFailure.Error != "stream reset" {
		t.Fatalf("second URL = %+v", b)
	}
}

func TestVisitorWindowRejectsMissedOrFailedRequests(t *testing.T) {
	for _, result := range []benchworkload.VisitorResult{{Missed: 1}, {Failures: 1}, {QueueExpired: 1}} {
		if err := visitorWindowError(result, nil); err == nil {
			t.Fatalf("accepted failed visitor window: %+v", result)
		}
	}
	if err := visitorWindowError(benchworkload.VisitorResult{Successes: 4}, nil); err != nil {
		t.Fatalf("rejected clean visitor window: %v", err)
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
