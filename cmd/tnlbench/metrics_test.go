package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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
		samples[0].Metrics["process_resident_memory_bytes"] != 1024 || len(samples[0].Metrics) != 1 {
		t.Fatalf("resource samples = %#v", samples)
	}
	if requestedFragment != "" {
		t.Fatalf("HTTP request included fragment %q", requestedFragment)
	}
}

func TestMetricsParserKeepsLabelsContainingSpaces(t *testing.T) {
	name := `tnl_control_requests_total{operation="POST /v1/routes",outcome="success"}`
	values := parseMetrics(name + " 3\n")
	if values[name] != 3 {
		t.Fatalf("metrics=%v", values)
	}
}

func TestFailedPublisherRetainsEarlyMetricsAndDatabaseSnapshot(t *testing.T) {
	metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/debug/database" {
			_, _ = w.Write([]byte(`{"sessions":[{"pid":1,"state":"active","wait_type":"Lock","blocking_pids":[2]}]}`))
			return
		}
		_, _ = w.Write([]byte("tnl_database_pool_acquired_connections 4\n"))
	}))
	defer metrics.Close()
	state := newCoordinatorState("early", 1, 1, 1)
	coordinator := httptest.NewServer(coordinatorHandler("secret", state))
	defer coordinator.Close()
	command := publisherCommand{
		workerCommand: workerCommand{CellID: "early", Suite: "scout", Axis: "active_routes", Repetition: 1, WorkerCount: 1, CoordinatorURL: coordinator.URL, CoordinatorToken: "secret"},
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
	if result.Failure.Stage != "setup" || len(result.Resources) < 2 || result.Resources[0].Moment != "before_activation" ||
		len(result.DatabaseDiagnostics) != 1 || result.DatabaseDiagnostics[0].Snapshot.Sessions[0].WaitType != "Lock" {
		t.Fatalf("result=%+v", result)
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
	if len(data) > 1<<20 {
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
	if len(samples) != 1 || samples[0].Error != "" || samples[0].Metrics["process_cpu_seconds_total"] != 1 {
		t.Fatalf("samples = %#v", samples)
	}
}
