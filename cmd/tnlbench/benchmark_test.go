package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
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
	return workloadOptions{Suite: "smoke", Server: "https://control.example.test", Mode: modeFreshHeld, Transport: "mixed", VisitorNetwork: "tcp", PublicURLs: 4, StartParallel: 4, FreshRate: 16,
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
	if len(observed) != maxPublisherObservations || dropped != 1 || observed[0].PublicURLID != "public_url_0" || !strings.Contains(observed[len(observed)-1].Detail, "benchmark could not complete") || strings.Contains(observed[len(observed)-1].Detail, "QUIC timeout") {
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

func TestSmokeSuiteBoundsEveryWorkloadDimension(t *testing.T) {
	for _, test := range []struct {
		name string
		set  func(*workloadOptions)
	}{
		{"concurrency", func(c *workloadOptions) { c.Concurrency = 100_000 }},
		{"queue slots", func(c *workloadOptions) { c.QueueSlots = 10_000 }},
		{"payload bytes", func(c *workloadOptions) { c.PayloadBytes = 16 << 20 }},
		{"warmup", func(c *workloadOptions) { c.Warmup = 5 * time.Minute }},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := smokeOptions()
			test.set(&options)
			if _, err := options.plan(); err == nil {
				t.Fatal("smoke accepted a target-sized workload dimension")
			}
			options.Suite = "target"
			if _, err := options.plan(); err != nil {
				t.Fatalf("target rejected its documented bounds: %v", err)
			}
		})
	}
}

func TestTargetWorkloadModesRequireMatchingTraffic(t *testing.T) {
	for _, test := range []struct {
		mode        benchmarkMode
		fresh, held int
		direction   string
		mbits       int64
		streams     int
	}{
		{mode: modeFresh, fresh: 16},
		{mode: modeHeld, held: 16},
		{mode: modeBandwidth, direction: "downstream", mbits: 100, streams: 64},
		{mode: modeCombined, fresh: 16, held: 4, direction: "bidirectional", mbits: 100, streams: 64},
	} {
		options := smokeOptions()
		options.Suite, options.Mode = benchmarkTarget, test.mode
		options.FreshRate, options.HeldStreams = test.fresh, test.held
		options.BandwidthDirection, options.BandwidthMbits, options.BandwidthStreams = test.direction, test.mbits, test.streams
		plan, err := options.plan()
		if err != nil || plan.Workload.Mode != test.mode || plan.Workload.BandwidthMbits != test.mbits {
			t.Fatalf("%s plan = %+v, %v", test.mode, plan, err)
		}
		options.FreshRate++
		if !test.mode.fresh() {
			if _, err := options.plan(); err == nil {
				t.Fatalf("%s accepted unselected fresh traffic", test.mode)
			}
		}
	}
	options := smokeOptions()
	options.StartParallel = 5
	if _, err := options.plan(); err == nil {
		t.Fatal("smoke accepted a different activation rate")
	}
	options.Suite = benchmarkTarget
	if _, err := options.plan(); err != nil {
		t.Fatalf("target rejected bounded activation: %v", err)
	}
	options.Mode, options.FreshRate, options.HeldStreams = modeBandwidth, 0, 0
	options.BandwidthDirection, options.BandwidthMbits, options.BandwidthStreams = "sideways", 100, 64
	if _, err := options.plan(); err == nil {
		t.Fatal("accepted unknown bandwidth direction")
	}
	options.BandwidthDirection, options.BandwidthMbits, options.BandwidthStreams = "downstream", 10_000, 1
	if _, err := options.plan(); err == nil {
		t.Fatal("accepted per-stream rate exceeding the workload limit")
	}
}

func TestCombinedWindowChecksFreshHeldAndBidirectionalBandwidth(t *testing.T) {
	server := httptest.NewTLSServer(benchworkload.Origin(32))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	visitor := benchworkload.Visitor{Roots: roots, PayloadBytes: 32}
	options := smokeOptions()
	options.Suite, options.Mode = benchmarkTarget, modeCombined
	options.FreshRate, options.HeldStreams = 8, 1
	options.BandwidthDirection, options.BandwidthMbits, options.BandwidthStreams = "bidirectional", 1, 2
	command := runCommand{workloadOptions: options}
	held, err := openHeldStreams(t.Context(), visitor, []string{server.URL}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer closeHeldStreams(held)
	before := heldBytes(held)
	fresh, bandwidth, err := command.runWindow(t.Context(), visitor, []string{server.URL}, 250*time.Millisecond, nil, false)
	if err != nil || fresh.Err() != nil || fresh.Scheduled != 2 || fresh.Successes != 2 || bandwidth == nil || bandwidth.Err() != nil || bandwidth.UploadBytes == 0 || bandwidth.DownloadBytes == 0 {
		t.Fatalf("combined window: fresh=%+v bandwidth=%+v error=%v", fresh, bandwidth, err)
	}
	if progress, err := checkHeldProgress(held, before); err != nil || progress.Progressing != 1 || progress.Bytes == 0 {
		t.Fatalf("held progress = %+v, %v", progress, err)
	}
}

func TestHeldWindowRejectsAnOpenStreamThatStopsDelivering(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-TNL-Bench-Host", r.Host)
		_, _ = w.Write([]byte("t"))
		_ = http.NewResponseController(w).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	visitor := benchworkload.Visitor{Roots: roots}
	held, err := openHeldStreams(t.Context(), visitor, []string{server.URL}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer closeHeldStreams(held)
	before := heldBytes(held)
	options := smokeOptions()
	options.Mode = modeHeld
	if _, _, err := (runCommand{workloadOptions: options}).runWindow(t.Context(), visitor, []string{server.URL}, 50*time.Millisecond, nil, false); err != nil {
		t.Fatal(err)
	}
	if progress, err := checkHeldProgress(held, before); err == nil || progress.Progressing != 0 {
		t.Fatalf("stalled held stream = %+v, %v", progress, err)
	}
}

func TestBandwidthWarmupFailurePersistsTransferSample(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-TNL-Bench-Host", r.Host)
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	options := smokeOptions()
	options.Mode, options.FreshRate, options.HeldStreams = modeBandwidth, 0, 0
	options.BandwidthDirection, options.BandwidthMbits, options.BandwidthStreams = "downstream", 1, 1
	options.Warmup = 50 * time.Millisecond
	var progress bytes.Buffer
	bandwidth, err := (runCommand{workloadOptions: options}).warmupPhase(t.Context(), benchworkload.Visitor{Roots: roots}, []string{server.URL}, &progress, "warmup")
	if err == nil || bandwidth == nil || bandwidth.Failures != 1 || len(bandwidth.FailureSamples) != 1 || !strings.Contains(bandwidth.FailureSamples[0], "unverified bandwidth response") {
		t.Fatalf("failed warmup = %+v, %v", bandwidth, err)
	}
	encoded, err := json.Marshal(benchmarkResult{SchemaVersion: 3, WarmupBandwidth: bandwidth})
	if err != nil {
		t.Fatal(err)
	}
	var restored benchmarkResult
	if err := json.Unmarshal(encoded, &restored); err != nil || restored.WarmupBandwidth == nil || len(restored.WarmupBandwidth.FailureSamples) != 1 {
		t.Fatalf("lost bandwidth failure sample: %+v, %v", restored.WarmupBandwidth, err)
	}
	var report bytes.Buffer
	if err := printResult(&report, restored); err != nil || !strings.Contains(report.String(), "first warmup failure: unverified bandwidth response: status 404") {
		t.Fatalf("warmup report = %q, %v", report.String(), err)
	}
}

func TestBandwidthWarmupRecordsLateCompleteTransferAndContinues(t *testing.T) {
	origin := benchworkload.Origin(1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bandwidth" {
			time.Sleep(1250 * time.Millisecond)
		}
		origin.ServeHTTP(w, r)
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	options := smokeOptions()
	options.Mode, options.FreshRate, options.HeldStreams = modeBandwidth, 0, 0
	options.BandwidthDirection, options.BandwidthMbits, options.BandwidthStreams = "downstream", 1, 1
	options.Warmup = 50 * time.Millisecond
	var progress bytes.Buffer
	bandwidth, err := (runCommand{workloadOptions: options}).warmupPhase(t.Context(), benchworkload.Visitor{Roots: roots}, []string{server.URL}, &progress, "warmup")
	if err != nil || bandwidth == nil || !errors.Is(bandwidth.Err(), benchworkload.ErrBandwidthLate) || bandwidth.CorrectnessErr() != nil ||
		bandwidth.DownloadBytes != 6250 || !strings.Contains(progress.String(), "measuring anyway") {
		t.Fatalf("late complete warmup = %+v, %v; output=%q", bandwidth, err, progress.String())
	}
}

func TestReportReadsExistingAndGenericBenchmarkResults(t *testing.T) {
	for _, test := range []struct {
		name    string
		version int
		server  string
	}{
		{name: "existing staging", version: 1, server: "https://control.tnl.wtf"},
		{name: "selected deployment", version: 2, server: "https://control.example.test"},
		{name: "capacity workload", version: 3, server: "https://control.example.test"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			result := benchmarkResult{
				SchemaVersion: test.version, RunID: "run-1", Plan: benchmarkPlan{Server: test.server}, Status: "passed",
			}
			if test.version >= 2 {
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
			if test.version >= 2 && !strings.Contains(output.String(), "public_url_1 quic: 1/4 successful; 3 missed") {
				t.Fatalf("missing per-URL report: %s", output.String())
			}
		})
	}
}

func TestReportIncludesBandwidthAndHeldProgress(t *testing.T) {
	result := benchmarkResult{RunID: "run-capacity", Status: "passed", Activation: time.Second, Plan: benchmarkPlan{Workload: workloadSummary{Mode: modeCombined}},
		PublicURLInfo: []benchmarkPublicURL{{PublicURL: "https://example.test", Transport: "quic"}},
		DirectHeld:    &heldProgress{Open: 2, Progressing: 2, Bytes: 100},
		SteadyHeld:    []heldProgress{{Open: 2, Progressing: 2, Bytes: 200}},
		DirectBandwidth: &benchworkload.BandwidthResult{Direction: "upstream", StreamsPerDirection: 2, TargetBytesPerSecond: 125000,
			UploadBytes: 125000, ExpectedUploadBytes: 125000, UploadBytesPerSecond: 125000},
		SteadyBandwidth: []benchworkload.BandwidthResult{{Direction: "upstream", StreamsPerDirection: 2,
			TargetBytesPerSecond: 125000, UploadBytes: 125000, ExpectedUploadBytes: 125000, UploadBytesPerSecond: 125000,
			Streams: []benchworkload.BandwidthStreamResult{{URL: "https://example.test", Direction: "upstream", Bytes: 125000, ExpectedBytes: 125000,
				FirstByteDelay: time.Millisecond, LastByteDelay: time.Second}}}}}
	var output bytes.Buffer
	if err := printResult(&output, result); err != nil || !strings.Contains(output.String(), "activation: 0 public URLs in 1s") || !strings.Contains(output.String(), "server held 1: 2/2 progressing; 200 bytes") ||
		!strings.Contains(output.String(), "server bandwidth 1: upstream, 2 streams/direction, target 1.0 Mbit/s/direction; upload 125000/125000 bytes") ||
		!strings.Contains(output.String(), "https://example.test quic: 1 streams, 125000/125000 bytes; latest first byte 1ms; last byte 1s") {
		t.Fatalf("capacity report = %q, %v", output.String(), err)
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
	if result.SchemaVersion != 3 || result.Plan.SchemaVersion != 3 || result.Status != "interrupted" || result.CleanupStatus != "not_needed" || result.CleanupExact || len(result.PublicURLs) != 0 {
		t.Fatalf("canceled result = %+v", result)
	}
	if strings.Contains(progress.String(), "connecting to") {
		t.Fatalf("canceled run attempted publishing: %s", progress.String())
	}
}

func TestPhaseReportsProgressWhileRunning(t *testing.T) {
	var progress bytes.Buffer
	heartbeat := make(chan struct{})
	writer := &phaseHeartbeatWriter{Buffer: &progress, heartbeat: heartbeat}
	if err := reportPhaseEvery(writer, "local baseline", time.Second, time.Millisecond, func() error {
		select {
		case <-heartbeat:
			return nil
		case <-time.After(time.Second):
			return errors.New("no progress heartbeat while phase was running")
		}
	}); err != nil {
		t.Fatal(err)
	}
	for _, message := range []string{"local baseline started", "local baseline still running", "local baseline complete"} {
		if !strings.Contains(progress.String(), message) {
			t.Fatalf("progress missing %q: %s", message, progress.String())
		}
	}
}

type phaseHeartbeatWriter struct {
	*bytes.Buffer
	heartbeat chan struct{}
	once      sync.Once
}

func (w *phaseHeartbeatWriter) Write(data []byte) (int, error) {
	if bytes.Contains(data, []byte("still running")) {
		w.once.Do(func() { close(w.heartbeat) })
	}
	return w.Buffer.Write(data)
}
