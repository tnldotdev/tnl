package main

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/observability"
)

func TestSampleResourcesUsesRoleMetadataWithoutSendingFragment(t *testing.T) {
	requestedFragment := "not-called"
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requestedFragment = request.URL.Fragment
		_, _ = response.Write([]byte("process_resident_memory_bytes 1024\nignored_metric 1\n"))
	}))
	defer server.Close()

	samples := sampleResources(t.Context(), []string{server.URL + "/metrics#relay-a"}, "loaded")
	if len(samples) != 1 || samples[0].Role != "relay" || samples[0].Identity == "" ||
		metricValueForTest(samples[0], "process_resident_memory_bytes") != 1024 || len(samples[0].Metrics) != 1 {
		t.Fatalf("resource samples = %#v", samples)
	}
	if requestedFragment != "" {
		t.Fatalf("HTTP request included fragment %q", requestedFragment)
	}
}

func TestMetricsParserKeepsLabelsContainingSpaces(t *testing.T) {
	name := `tnl_control_requests_total{operation="POST /v1/routes",outcome="success"}`
	values := metricsForTest(name + " 3 12345\n")
	if len(values) != 1 || values[0].Metric[0].GetUntyped().GetValue() != 3 ||
		values[0].Metric[0].Label[0].GetValue() != "POST /v1/routes" || values[0].Metric[0].GetTimestampMs() != 12345 {
		t.Fatalf("metrics=%v", values)
	}
}

func TestNonzeroFailedPublisherCollectsFailureMetricsWithoutRoutineMetrics(t *testing.T) {
	metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/debug/database" {
			_, _ = w.Write([]byte(`{"sessions":[{"pid":1,"state":"active","wait_type":"Lock","transaction_age_seconds":null,"query_age_seconds":null,"blocking_pids":[2]}]}`))
			return
		}
		_, _ = w.Write([]byte("tnl_database_pool_acquired_connections 4\n"))
	}))
	defer metrics.Close()
	state := newCoordinatorState("early", 2, 1, 1)
	coordinator := httptest.NewServer(coordinatorHandler("secret", state))
	defer coordinator.Close()
	command := publisherCommand{
		workerCommand: workerCommand{CellID: "early", Suite: "scout", Axis: "active_routes", Repetition: 1, WorkerIndex: 1, WorkerCount: 2, CoordinatorURL: coordinator.URL, CoordinatorToken: "secret"},
		ControlCAFile: filepath.Join(t.TempDir(), "missing-ca"), Routes: 1, AssignedRoutes: 1, PayloadBytes: 16, Timeout: time.Second,
		MetricsURLs: []string{metrics.URL + "/metrics#control"}, DiagnosticURLs: []string{metrics.URL + "/debug/database"},
	}
	if err := command.run(t.Context()); err == nil {
		t.Fatal("expected setup failure")
	}
	data, err := coordinatorResults(t.Context(), &coordinatorClient{baseURL: coordinator.URL, token: "secret"}, true)
	if err != nil {
		t.Fatal(err)
	}
	var result benchmarkResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Failure.Stage != "setup" || len(result.Resources) != 1 || result.Resources[0].Moment != "failure" ||
		metricValueForTest(result.Resources[0], "tnl_database_pool_acquired_connections") != 4 || len(result.DatabaseDiagnostics) != 1 ||
		result.DatabaseDiagnostics[0].Snapshot.Sessions[0].WaitType != "Lock" ||
		result.DatabaseDiagnostics[0].Snapshot.Sessions[0].TransactionAgeSeconds != nil {
		t.Fatalf("result=%+v", result)
	}
	reportResult := reportTestResult("early", 0, 1, "publisher", 1, 2, "failed", time.Millisecond)
	reportResult.DatabaseDiagnostics = result.DatabaseDiagnostics
	report, err := buildReport([]benchmarkResult{reportResult})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Cells) != 1 || !strings.Contains(strings.Join(report.Cells[0].BottleneckEvidence, "\n"), "oldest transaction unavailable") {
		t.Fatalf("report did not preserve unavailable database age: %+v", report)
	}
	data, err = json.Marshal(controlstate.DatabaseSession{})
	if err != nil || !strings.Contains(string(data), `"transaction_age_seconds":null`) || !strings.Contains(string(data), `"query_age_seconds":null`) {
		t.Fatalf("unavailable database metadata = %s, %v", data, err)
	}
	var legacy controlstate.DatabaseSession
	if err := json.Unmarshal([]byte(`{"transaction_age_seconds":1.5,"query_age_seconds":2.5}`), &legacy); err != nil ||
		legacy.TransactionAgeSeconds == nil || *legacy.TransactionAgeSeconds != 1.5 {
		t.Fatalf("legacy numeric database metadata = %+v, %v", legacy, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := sampleDatabaseDiagnostics(ctx, command.DiagnosticURLs); len(got) != 1 || got[0].Error != "" {
		t.Fatalf("canceled workload prevented diagnostics: %+v", got)
	}
}

func TestResourceSamplerBoundsPayload(t *testing.T) {
	requests := make(chan struct{}, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("tnl_sample{label=\"" + strings.Repeat("x", 600<<10) + "\"} 1\n"))
		select {
		case requests <- struct{}{}:
		default:
		}
	}))
	defer server.Close()
	sampler := startResourceSampler(t.Context(), []string{server.URL + "#control"}, time.Millisecond)
	defer sampler.Stop()
	for range 3 {
		select {
		case <-requests:
		case <-time.After(time.Second):
			t.Fatal("metrics sampling stalled")
		}
	}
	samples := sampler.Stop()
	if sampler.dropped == 0 {
		t.Fatal("unbounded telemetry retained")
	}
	data, err := json.Marshal(samples)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 512<<10 {
		t.Fatalf("retained %d telemetry bytes", len(data))
	}
}

func TestStoppingResourceSamplerDoesNotCancelInFlightSample(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		startedOnce.Do(func() { close(started) })
		<-release
		_, _ = response.Write([]byte("process_cpu_seconds_total 1\n"))
	}))
	defer server.Close()

	sampler := startResourceSampler(t.Context(), []string{server.URL + "#control"}, time.Millisecond)
	<-started
	done := make(chan []resourceSample, 1)
	go func() { done <- sampler.Stop() }()
	close(release)
	samples := <-done
	if len(samples) != 1 || samples[0].Error != "" || metricValueForTest(samples[0], "process_cpu_seconds_total") != 1 {
		t.Fatalf("samples = %#v", samples)
	}
}

func metricsForTest(text string) []*dto.MetricFamily {
	metrics, err := observability.ParseMetrics(strings.NewReader(text))
	if err != nil {
		panic(err)
	}
	return metrics
}

func metricValueForTest(sample resourceSample, name string) float64 {
	value, _ := scalarMetric(sample.Metrics, name)
	return value
}

func TestProductionMetricsRoundTripSummarizesWorkloadOnly(t *testing.T) {
	metrics := observability.New("control")
	server := httptest.NewServer(metrics.Handler())
	defer server.Close()
	endpoints := []string{server.URL + "/metrics#control"}
	metrics.ObserveOperation("HeartbeatRouteSession", nil, time.Second) // Setup.
	resources := sampleBoundaryResources(t.Context(), endpoints, "ready")
	for range 3 {
		metrics.ObserveOperation("HeartbeatRouteSession", nil, 10*time.Millisecond)
	}
	metrics.ObserveOperation("HeartbeatRouteSession", errors.New("failed"), 3*time.Minute)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	resources = append(resources, sampleBoundaryResources(canceled, endpoints, "loaded")...)
	metrics.ObserveOperation("HeartbeatRouteSession", nil, time.Hour) // Cleanup.
	encoded, err := json.Marshal(resources)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []resourceSample
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	reports := serverDurationReports(decoded)
	if len(reports) != 1 || !reports[0].Complete || reports[0].Error != "" || len(reports[0].Durations) != 2 {
		t.Fatalf("intervals = %+v; samples = %+v", reports, decoded)
	}
	for _, summary := range reports[0].Durations {
		if summary.Labels["outcome"] == "success" {
			if summary.Count != 3 || math.Abs(summary.SumSeconds-0.03) > 1e-9 || summary.P95Seconds == nil ||
				math.Abs(*summary.P95Seconds-0.00975) > 1e-9 {
				t.Fatalf("setup or cleanup contaminated summary: %+v", summary)
			}
		} else if summary.Count != 1 || summary.SumSeconds != 180 || summary.P95Seconds != nil {
			t.Fatalf("overflow error observations = %+v", summary)
		}
	}
	text := formatReportMarkdown(benchmarkReport{Cells: []cellReport{{ServerDurations: reports}}})
	for _, want := range []string{"approximate histogram", "HeartbeatRouteSession", "complete: true", "n/a"} {
		if !strings.Contains(text, want) {
			t.Fatalf("markdown missing %q: %s", want, text)
		}
	}
}

func TestMetricsScrapeRejectsMalformedAndOversizedPayloads(t *testing.T) {
	for name, body := range map[string]string{
		"invalid":                 "tnl_broken{label=broken} 1\n",
		"oversized":               "# " + strings.Repeat("x", 2<<20) + "\n",
		"nonfinite":               "tnl_broken NaN\n",
		"invalid infinite bucket": "# TYPE tnl_duration_seconds histogram\ntnl_duration_seconds_bucket{le=\"+Inf\"} 1\ntnl_duration_seconds_count 2\ntnl_duration_seconds_sum 3\n",
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			samples := sampleResources(t.Context(), []string{server.URL}, "ready")
			if len(samples) != 1 || samples[0].Error == "" || len(samples[0].Metrics) != 0 {
				t.Fatalf("invalid scrape reported as data: %+v", samples)
			}
		})
	}
}

func TestPeriodicEvictionPreservesProductionMeasurementBoundaries(t *testing.T) {
	metrics := observability.New("control")
	metrics.ObserveOperation("CreateRouteSession", nil, time.Millisecond)
	var large atomic.Bool
	requests := make(chan struct{}, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if large.Load() {
			_, _ = w.Write([]byte("tnl_sample{label=\"" + strings.Repeat("x", 600<<10) + "\"} 1\n"))
			select {
			case requests <- struct{}{}:
			default:
			}
			return
		}
		metrics.Handler().ServeHTTP(w, r)
	}))
	defer server.Close()
	endpoints := []string{server.URL + "#control"}
	samples := sampleBoundaryResources(t.Context(), endpoints, "before_activation")
	large.Store(true)
	sampler := startResourceSampler(t.Context(), endpoints, time.Millisecond)
	defer sampler.Stop()
	for range 3 {
		select {
		case <-requests:
		case <-time.After(time.Second):
			t.Fatal("sampler stalled")
		}
	}
	samples = append(samples, sampler.Stop()...)
	large.Store(false)
	metrics.ObserveOperation("CreateRouteSession", nil, 2*time.Millisecond)
	samples = append(samples, sampleBoundaryResources(t.Context(), endpoints, "activated")...)
	if sampler.dropped == 0 {
		t.Fatal("test did not evict periodic samples")
	}
	reports := serverDurationReports(samples)
	if len(reports) != 1 || !reports[0].Complete || len(reports[0].Durations) != 1 || reports[0].Durations[0].Count != 1 {
		t.Fatalf("eviction affected boundaries: %+v", reports)
	}
}

func TestBoundaryPayloadLimitIsExplicit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("tnl_sample{label=\"" + strings.Repeat("x", 200<<10) + "\"} 1\n"))
	}))
	defer server.Close()
	samples := sampleBoundaryResources(t.Context(), []string{server.URL}, "ready")
	if len(samples) != 1 || samples[0].Error != "boundary metrics payload limit exceeded" || samples[0].Metrics != nil {
		t.Fatalf("oversized boundary disappeared: %+v", samples)
	}
}
