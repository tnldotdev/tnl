package main

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestBenchmarkCertificate(t *testing.T) {
	certificates, roots, err := benchmarkCertificates("run.bench.test", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(certificates) != 2 || certificates[1].Leaf == nil {
		t.Fatal("certificate omitted leaf")
	}
	if _, err := certificates[1].Leaf.Verify(x509.VerifyOptions{
		DNSName: "r00001.run.bench.test", Roots: roots,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSummarize(t *testing.T) {
	got := summarize([]time.Duration{5 * time.Millisecond, time.Millisecond, 3 * time.Millisecond, 2 * time.Millisecond})
	if got.P50 != 2 || got.P95 != 5 || got.Max != 5 {
		t.Fatalf("summary = %#v", got)
	}
}

func TestParseMetrics(t *testing.T) {
	values := parseMetrics("# HELP ignored\ntnl_worker_routes_active 12\nprocess_resident_memory_bytes 4096\nmetric{label=\"x\"} 1\n")
	if values["tnl_worker_routes_active"] != 12 || values["process_resident_memory_bytes"] != 4096 {
		t.Fatalf("metrics = %#v", values)
	}
}

func TestExpectedRoutes(t *testing.T) {
	if got := (cli{Routes: 12}).expectedRoutes(); got != 12 {
		t.Fatalf("default expected routes = %d, want 12", got)
	}
	if got := (cli{Routes: 12, ExpectedRoutes: 50}).expectedRoutes(); got != 50 {
		t.Fatalf("explicit expected routes = %d, want 50", got)
	}
}

func TestValidateExpectedRoutes(t *testing.T) {
	flags := cli{
		PublicAddress: "bench.test:443", HostnameSuffix: "bench.test",
		Routes: 12, ExpectedRoutes: 11, DriverCount: 1, Parallel: 1, PayloadBytes: 1, Timeout: time.Second,
	}
	if err := flags.Validate(); err == nil {
		t.Fatal("expected aggregate route count below shard size to fail validation")
	}
	flags.ExpectedRoutes = 50
	if err := flags.Validate(); err != nil {
		t.Fatalf("valid aggregate route count: %v", err)
	}
}

func TestWaitWorkerRoutesAcceptsAggregateAboveExpected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte("tnl_worker_routes_active 13\ntnl_worker_route_capacity 20\n"))
	}))
	defer server.Close()

	samples, err := waitWorkerRoutes(context.Background(), []string{server.URL}, 12)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 || samples[0].Routes != 13 {
		t.Fatalf("samples = %#v", samples)
	}
}

func TestCleanupRoutesDeletesCapturedRouteIDs(t *testing.T) {
	cleaner := new(cleanerStub)
	processes := make([]*routeProcess, 2)
	contexts := make([]context.Context, len(processes))
	for index := range processes {
		routeCtx, cancel := context.WithCancel(context.Background())
		contexts[index] = routeCtx
		done := make(chan error, 1)
		done <- nil
		processes[index] = &routeProcess{routeID: "route_" + string(rune('a'+index)), cancel: cancel, done: done}
	}
	timings, err := cleanupRoutes(context.Background(), cli{Parallel: 2}, cleaner, processes)
	if err != nil {
		t.Fatal(err)
	}
	if len(timings) != len(processes) {
		t.Fatalf("timings = %d, want %d", len(timings), len(processes))
	}
	for index, ctx := range contexts {
		if ctx.Err() != context.Canceled {
			t.Fatalf("context %d was not canceled", index)
		}
	}
	slices.Sort(cleaner.routeIDs)
	if !slices.Equal(cleaner.routeIDs, []string{"route_a", "route_b"}) {
		t.Fatalf("deleted routes = %v", cleaner.routeIDs)
	}
}

type cleanerStub struct {
	mu       sync.Mutex
	routeIDs []string
}

func (c *cleanerStub) DeleteRoute(_ context.Context, routeID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.routeIDs = append(c.routeIDs, routeID)
	return nil
}
