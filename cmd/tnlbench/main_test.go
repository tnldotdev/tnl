package main

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
)

func TestBenchmarkCertificate(t *testing.T) {
	hostnames := []string{"tnlbench-d3-r0.run.bench.test", "exact-name.run.bench.test"}
	certificates, roots, err := benchmarkCertificates(hostnames)
	if err != nil {
		t.Fatal(err)
	}
	if len(certificates) != 2 || certificates[1].Leaf == nil {
		t.Fatal("certificate omitted leaf")
	}
	if certificates[1].Leaf.Subject.CommonName != hostnames[1] ||
		!slices.Equal(certificates[1].Leaf.DNSNames, []string{hostnames[1]}) {
		t.Fatalf("certificate names = %q, %v", certificates[1].Leaf.Subject.CommonName, certificates[1].Leaf.DNSNames)
	}
	if _, err := certificates[1].Leaf.Verify(x509.VerifyOptions{
		DNSName: hostnames[1], Roots: roots,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestBenchmarkHostnamesAreUniqueSingleLabelClaims(t *testing.T) {
	seen := make(map[string]struct{})
	for driverIndex := range 8 {
		for routeIndex := range 5000 {
			label := benchmarkRouteLabel(driverIndex, routeIndex)
			if strings.Contains(label, ".") {
				t.Fatalf("label %q contains a dot", label)
			}
			if canonical, err := naming.CanonicalizeHostname(label); err != nil || canonical != label {
				t.Fatalf("label %q is invalid: %v", label, err)
			}
			hostname := benchmarkHostname(driverIndex, routeIndex, "run.bench.test")
			if _, found := seen[hostname]; found {
				t.Fatalf("duplicate hostname %q", hostname)
			}
			seen[hostname] = struct{}{}
		}
	}
}

func TestBenchmarkHostnameSuffix(t *testing.T) {
	valid := serverv1.Capabilities{
		HostnameAuthorization: []serverv1.CapabilitiesHostnameAuthorization{serverv1.LocalClaim},
		LocalClaim:            &serverv1.LocalClaimCapabilities{Suffix: "run.bench.test"},
	}
	if suffix, err := benchmarkHostnameSuffix(valid, "run.bench.test"); err != nil || suffix != "run.bench.test" {
		t.Fatalf("valid capability = %q, %v", suffix, err)
	}

	for name, capabilities := range map[string]serverv1.Capabilities{
		"authorization omitted": {LocalClaim: valid.LocalClaim},
		"metadata omitted": {
			HostnameAuthorization: []serverv1.CapabilitiesHostnameAuthorization{serverv1.LocalClaim},
		},
		"invalid advertised suffix": {
			HostnameAuthorization: []serverv1.CapabilitiesHostnameAuthorization{serverv1.LocalClaim},
			LocalClaim:            &serverv1.LocalClaimCapabilities{Suffix: "Run.Bench.Test"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := benchmarkHostnameSuffix(capabilities, "run.bench.test"); err == nil {
				t.Fatal("expected capability validation to fail")
			}
		})
	}
	if _, err := benchmarkHostnameSuffix(valid, "other.bench.test"); err == nil {
		t.Fatal("expected configured suffix mismatch to fail")
	}
}

func TestSummarize(t *testing.T) {
	got := summarize([]time.Duration{5 * time.Millisecond, time.Millisecond, 3 * time.Millisecond, 2 * time.Millisecond})
	if got.P50 != 2 || got.P95 != 5 || got.Max != 5 {
		t.Fatalf("summary = %#v", got)
	}
}

func TestParseMetrics(t *testing.T) {
	values := parseMetrics("# HELP ignored\ntnl_worker_routes_active 12\nprocess_resident_memory_bytes 4096\nprocess_max_fds 1048576\nmetric{label=\"x\"} 1\n")
	if values["tnl_worker_routes_active"] != 12 || values["process_resident_memory_bytes"] != 4096 ||
		values["process_max_fds"] != 1048576 || values[`metric{label="x"}`] != 1 {
		t.Fatalf("metrics = %#v", values)
	}
}

func TestSampleWorkersIncludesMaxFDs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte("process_open_fds 17\nprocess_max_fds 1048576\n" +
			"tnl_tailcat_failures_total{operation=\"start\",reason=\"process_file_limit\"} 2\n" +
			"tnl_tailcat_failures_total{operation=\"start\",reason=\"system_file_limit\"} 1\n"))
	}))
	defer server.Close()

	samples, err := sampleWorkers(context.Background(), []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 || samples[0].OpenFDs != 17 || samples[0].MaxFDs != 1048576 ||
		samples[0].TailcatProcessFileLimitStartFailures != 2 || samples[0].TailcatSystemFileLimitStartFailures != 1 {
		t.Fatalf("samples = %#v", samples)
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
	routeCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		<-routeCtx.Done()
		cleaner.record("stop")
		done <- nil
	}()
	processes := []*routeProcess{{
		routeID: "route_a", claimID: "claim_a", claimOwner: cleaner, cancel: cancel, done: done,
	}}
	timings, err := cleanupRoutes(context.Background(), cli{Parallel: 1}, cleaner, processes)
	if err != nil {
		t.Fatal(err)
	}
	if len(timings) != len(processes) {
		t.Fatalf("timings = %d, want %d", len(timings), len(processes))
	}
	if routeCtx.Err() != context.Canceled {
		t.Fatal("publisher context was not canceled")
	}
	if !slices.Equal(cleaner.events, []string{"stop", "delete:route_a", "release:claim_a"}) {
		t.Fatalf("cleanup events = %v", cleaner.events)
	}
}

func TestCleanupRoutesReleasesClaimWithoutRoute(t *testing.T) {
	cleaner := new(cleanerStub)
	done := make(chan error, 1)
	done <- errors.New("route creation failed")
	process := &routeProcess{
		claimID: "claim_partial", claimOwner: cleaner, cancel: func() {}, done: done,
	}
	_, err := cleanupRoutes(context.Background(), cli{Parallel: 1}, cleaner, []*routeProcess{process})
	if err == nil || !strings.Contains(err.Error(), "route creation failed") {
		t.Fatalf("cleanup error = %v", err)
	}
	if !slices.Equal(cleaner.events, []string{"release:claim_partial"}) {
		t.Fatalf("cleanup events = %v", cleaner.events)
	}
}

type cleanerStub struct {
	mu     sync.Mutex
	events []string
}

func (c *cleanerStub) DeleteRoute(_ context.Context, routeID string) error {
	c.record("delete:" + routeID)
	return nil
}

func (c *cleanerStub) ReleaseHostnameClaim(_ context.Context, claimID string) error {
	c.record("release:" + claimID)
	return nil
}

func (c *cleanerStub) record(event string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, event)
}
