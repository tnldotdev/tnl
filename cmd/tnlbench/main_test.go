package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
)

func TestBenchmarkCertificate(t *testing.T) {
	hostnames := []string{"tnlbench-d3-r0.run.bench.test", "exact-name.run.bench.test"}
	certificates, roots, err := benchmarkCertificates(hostnames, "", "")
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

func TestLoadBenchmarkCertificate(t *testing.T) {
	hostname := "route.run.bench.test"
	generated, _, err := benchmarkCertificates([]string{hostname}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var certificatePEM []byte
	for _, certificate := range generated[0].Certificate {
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(generated[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certificatePath := filepath.Join(directory, "route.crt")
	keyPath := filepath.Join(directory, "route.key")
	if err := os.WriteFile(certificatePath, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, roots, err := benchmarkCertificates([]string{hostname}, certificatePath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].Leaf == nil || roots != nil {
		t.Fatalf("loaded certificate = %d, leaf %v, roots %v", len(loaded), loaded[0].Leaf, roots)
	}
	if _, _, err := benchmarkCertificates([]string{"other.bench.test"}, certificatePath, keyPath); err == nil {
		t.Fatal("certificate hostname mismatch succeeded")
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
		HostnameAuthorization: []serverv1.CapabilitiesHostnameAuthorization{serverv1.LocalHostnames},
		LocalHostnames:        &serverv1.LocalHostnameCapabilities{Suffix: "run.bench.test"},
	}
	if suffix, err := benchmarkHostnameSuffix(valid, "run.bench.test"); err != nil || suffix != "run.bench.test" {
		t.Fatalf("valid capability = %q, %v", suffix, err)
	}

	for name, capabilities := range map[string]serverv1.Capabilities{
		"authorization omitted": {LocalHostnames: valid.LocalHostnames},
		"metadata omitted": {
			HostnameAuthorization: []serverv1.CapabilitiesHostnameAuthorization{serverv1.LocalHostnames},
		},
		"invalid advertised suffix": {
			HostnameAuthorization: []serverv1.CapabilitiesHostnameAuthorization{serverv1.LocalHostnames},
			LocalHostnames:        &serverv1.LocalHostnameCapabilities{Suffix: "Run.Bench.Test"},
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

func TestParseMetrics(t *testing.T) {
	values := parseMetrics("# HELP ignored\ntnl_worker_routes_routable 12\nprocess_resident_memory_bytes 4096\nprocess_max_fds 1048576\nmetric{label=\"x\"} 1\n")
	if values["tnl_worker_routes_routable"] != 12 || values["process_resident_memory_bytes"] != 4096 ||
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

func TestTopologyHardCutover(t *testing.T) {
	for _, topology := range []string{"standalone", "split"} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse(benchmarkCLIArguments(topology)); err != nil {
			t.Fatalf("parse topology %q: %v", topology, err)
		}
	}
	for _, topology := range []string{"single-node", "ha"} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse(benchmarkCLIArguments(topology)); err == nil {
			t.Fatalf("legacy topology %q was accepted", topology)
		}
	}
}

func benchmarkCLIArguments(topology string) []string {
	return []string{
		"--topology", topology,
		"--server", "https://control.bench.test",
		"--login-token", "token",
		"--public-address", "bench.test:443",
		"--hostname-suffix", "bench.test",
	}
}

func TestValidateExpectedRoutes(t *testing.T) {
	flags := cli{
		PublicAddress: "bench.test:443", HostnameSuffix: "bench.test",
		Routes: 12, ExpectedRoutes: 11, DriverCount: 1, Parallel: 1, PayloadBytes: 1, Timeout: time.Second, Repetition: 1,
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
		_, _ = response.Write([]byte("tnl_worker_routes_routable 13\ntnl_worker_route_capacity 20\n"))
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

func TestCleanupRoutesLetsPublisherDeleteCapturedRouteIDs(t *testing.T) {
	cleaner := newCleanerStub("route_a")
	routeCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		<-routeCtx.Done()
		cleaner.record("stop")
		cleaner.deleteAsPublisher("route_a")
		done <- nil
	}()
	processes := []*routeProcess{{
		routeID: "route_a", hostnameID: "hostname_a", hostnameOwner: cleaner, cancel: cancel, done: done,
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
	if !slices.Equal(cleaner.events, []string{"stop", "publisher-delete:route_a", "list", "release:hostname_a"}) {
		t.Fatalf("cleanup events = %v", cleaner.events)
	}
}

func TestCleanupRoutesFallsBackWhenPublisherLeavesRoute(t *testing.T) {
	cleaner := newCleanerStub("route_a")
	routeCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		<-routeCtx.Done()
		cleaner.record("stop")
		done <- errors.New("publisher deletion failed")
	}()
	processes := []*routeProcess{{
		routeID: "route_a", hostnameID: "hostname_a", hostnameOwner: cleaner, cancel: cancel, done: done,
	}}
	_, err := cleanupRoutes(context.Background(), cli{Parallel: 1}, cleaner, processes)
	if err == nil || !strings.Contains(err.Error(), "publisher deletion failed") ||
		!strings.Contains(err.Error(), "publisher cleanup left 1 routes") {
		t.Fatalf("cleanup error = %v", err)
	}
	if !slices.Equal(cleaner.events, []string{"stop", "list", "delete:route_a", "list", "release:hostname_a"}) {
		t.Fatalf("cleanup events = %v", cleaner.events)
	}
}

func TestCleanupRoutesReleasesClaimWithoutRoute(t *testing.T) {
	cleaner := newCleanerStub()
	done := make(chan error, 1)
	done <- errors.New("route creation failed")
	process := &routeProcess{
		hostnameID: "hostname_partial", hostnameOwner: cleaner, cancel: func() {}, done: done,
	}
	_, err := cleanupRoutes(context.Background(), cli{Parallel: 1}, cleaner, []*routeProcess{process})
	if err == nil || !strings.Contains(err.Error(), "route creation failed") {
		t.Fatalf("cleanup error = %v", err)
	}
	if !slices.Equal(cleaner.events, []string{"release:hostname_partial"}) {
		t.Fatalf("cleanup events = %v", cleaner.events)
	}
}

type cleanerStub struct {
	mu     sync.Mutex
	events []string
	routes map[string]struct{}
}

func newCleanerStub(routeIDs ...string) *cleanerStub {
	cleaner := &cleanerStub{routes: make(map[string]struct{}, len(routeIDs))}
	for _, routeID := range routeIDs {
		cleaner.routes[routeID] = struct{}{}
	}
	return cleaner
}

func (c *cleanerStub) DeleteRoute(_ context.Context, routeID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, "delete:"+routeID)
	delete(c.routes, routeID)
	return nil
}

func (c *cleanerStub) ListRoutes(context.Context) ([]serverv1.Route, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, "list")
	routes := make([]serverv1.Route, 0, len(c.routes))
	for routeID := range c.routes {
		routes = append(routes, serverv1.Route{Id: routeID})
	}
	return routes, nil
}

func (c *cleanerStub) ReleaseHostname(_ context.Context, hostnameID string) error {
	c.record("release:" + hostnameID)
	return nil
}

func (c *cleanerStub) record(event string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, event)
}

func (c *cleanerStub) deleteAsPublisher(routeID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, "publisher-delete:"+routeID)
	delete(c.routes, routeID)
}
