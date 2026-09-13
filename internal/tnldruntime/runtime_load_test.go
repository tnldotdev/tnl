package tnldruntime

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

// All role instances and publishers share this test process, but use real
// listeners, authenticated HTTP APIs, publisher transports, route TLS and Pebble.
// The Compose task bounds their aggregate resources separately from PostgreSQL.
func TestLoadRuntimeVisitors(t *testing.T) {
	if os.Getenv("TNL_TEST_RUNTIME_LOAD") != "1" {
		t.Skip("run task go:test-runtime-load")
	}
	routes := runtimeLoadInt(t, "TNL_TEST_RUNTIME_ROUTES", 16, 2, 128)
	rate := runtimeLoadInt(t, "TNL_TEST_RUNTIME_RPS", 20, 1, 500)
	sources := runtimeLoadInt(t, "TNL_TEST_RUNTIME_SOURCES", 1, 1, 8)
	if sources > 1 && runtime.GOOS != "linux" {
		t.Skip("multiple loopback visitor source addresses require the Linux load task")
	}
	duration := 30 * time.Second
	if raw := os.Getenv("TNL_TEST_RUNTIME_DURATION"); raw != "" {
		var err error
		duration, err = time.ParseDuration(raw)
		if err != nil || duration < 10*time.Second || duration > 2*time.Minute {
			t.Fatal("runtime phase duration must be between 10s and 2m")
		}
	}
	t.Logf("runtime_load routes=%d rps=%d sources=%d phase_duration=%s visitor_workers=8 payload_bytes=32768 gomaxprocs=%d process_leases=30s renewals=10s", routes, rate, sources, duration, runtime.GOMAXPROCS(0))
	timeline := time.Now()
	trace := os.Getenv("TNL_TEST_RUNTIME_TRACE") == "1"
	var newOrders atomic.Int64
	fixture := newSplitPublishFixtureWithOptions(t, "runtime-load", splitPublishOptions{
		configureControlHTTP: func(client *http.Client) {
			if trace {
				traceRuntimeCertificateHTTP(t, client, timeline)
			}
		},
		configureProcess: func(cfg *tnldconfig.Config) {
			// The normal publisher heartbeat is 15s. The focused integration
			// fixture's accelerated 5s relay lease cannot cover sustained traffic.
			cfg.IngressLeaseDuration, cfg.RelayLeaseDuration = 30*time.Second, 30*time.Second
			cfg.LeaseRenewalInterval = 10 * time.Second
			// Use the documented production capacities, fixed across load sizes.
			// The focused fixture otherwise caps each relay at ten publishers.
			cfg.VisitorConnectionLimit, cfg.RouteConnectionLimit = 20000, 500
			cfg.PublisherConnectionLimit, cfg.RelayStreamCapacity = 1000, 4096
			cfg.QUICMaxIncomingStreams, cfg.QUICIdleTimeout = 4096, 45*time.Second
		},
	}, func(client *http.Client) {
		base := client.Transport
		client.Transport = splitACMERoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodPost && request.URL.Path == "/order-plz" {
				newOrders.Add(1)
			}
			return base.RoundTrip(request)
		})
	})
	var sourceCounter atomic.Uint64
	fixture.visitor.transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		source := byte((sourceCounter.Add(1)-1)%uint64(sources) + 1)
		dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, source)}}
		return dialer.DialContext(ctx, network, fixture.ingressConfig.IngressListen)
	}
	payload := bytes.Repeat([]byte("tnl!"), 8192)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "ready\n")
			w.(http.Flusher).Flush()
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-r.Context().Done():
					return
				case <-ticker.C:
					if _, err := io.WriteString(w, "tick\n"); err != nil {
						return
					}
					w.(http.Flusher).Flush()
				}
			}
		}
		_, _ = w.Write(payload)
	}))
	cleanupIntegrationHTTPServer(t, target, fixture.owner)
	quic, tcp := fixture.connectors()
	_, namespace, _ := strings.Cut(fixture.identity.hostname, ".")
	handles := make([]*integrationPublisher, routes)
	ready := make([]publisher.Event, routes)
	urls := make([]string, routes)
	started := make([]time.Time, routes)
	activation := time.Now()
	stopTimeline := func() {}
	if trace {
		stopTimeline = traceRuntimeCertificateState(t, fixture.inspect, timeline)
	}
	defer stopTimeline()
	logRuntimeLoadResources(t, "activation-before")
	for offset := 0; offset < routes; offset += 4 {
		for index := offset; index < min(offset+4, routes); index++ {
			config := fixture.identity.publisherConfig(target.URL, quic, tcp)
			// Exercise both real transports deterministically instead of counting
			// losing connection-race attempts as established publisher connections.
			if index%2 == 0 {
				config.TCPConnector, _ = disabledIntegrationConnector("QUIC cohort")
			} else {
				config.QUICConnector, _ = disabledIntegrationConnector("TLS/TCP cohort")
			}
			config.FallbackDelay = 250 * time.Millisecond
			config.Hostname = fmt.Sprintf("runtime-%d.%s", index, namespace)
			config.AllowedIPPrefixes = nil
			for source := 1; source <= sources; source++ {
				config.AllowedIPPrefixes = append(config.AllowedIPPrefixes, fmt.Sprintf("127.0.0.%d/32", source))
			}
			hostname := config.Hostname
			started[index] = time.Now()
			handles[index] = startOwnedIntegrationPublisher(t, fixture.owner, config, func() string {
				logRuntimeLoadResources(t, "activation-failure")
				return runtimeLoadPublisherDiagnostics(fixture.inspect, hostname)
			})
		}
		for index := offset; index < min(offset+4, routes); index++ {
			t.Logf("runtime_activation_wait index=%d elapsed=%s", index, time.Since(activation))
			ready[index] = waitForPublisherReady(t, handles[index])
			t.Logf("runtime_activation_ready index=%d elapsed=%s launch_to_ready_observed=%s", index, time.Since(activation), time.Since(started[index]))
			urls[index] = ready[index].PublicURL
			waitForReadyPublisherConnections(t, fixture.inspect, ready[index].RouteID, ready[index].RouteVersion, 2)
		}
	}
	waitForIngressRoutingCurrent(t, fixture.inspect, 1)
	stopTimeline()
	var installedOrders int
	if err := fixture.inspect.QueryRowContext(integrationOperationContext(t), `SELECT count(*) FROM control.acme_orders WHERE state = 'installed'`).Scan(&installedOrders); err != nil {
		t.Fatal(err)
	}
	if installedOrders != routes || newOrders.Load() != int64(routes) {
		t.Fatalf("issuance count: routes=%d installed=%d CA_new_orders=%d", routes, installedOrders, newOrders.Load())
	}
	t.Logf("runtime_issuance routes=%d installed=%d CA_new_orders=%d", routes, installedOrders, newOrders.Load())
	t.Logf("runtime_activation routes=%d elapsed=%s", routes, time.Since(activation))
	t.Logf("runtime_transport_cohorts quic_publishers=%d tls_tcp_publishers=%d connections_per_publisher=2", (routes+1)/2, routes/2)

	var streams []*runtimeLoadStream
	for _, url := range urls[:min(8, routes)] {
		streams = append(streams, startRuntimeLoadStream(t, fixture.visitor.transport, url))
	}
	defer func() {
		for _, stream := range streams {
			stream.stop(t)
		}
	}()
	logRuntimeLoadResources(t, "steady-before")
	metricsBefore := captureRuntimeLoadMetrics(t, fixture)
	onFailure := func(url string) {
		logRuntimeLoadResources(t, "visitor-first-failure")
		t.Logf("runtime_visitor_first_failure %s", runtimeLoadPublisherDiagnostics(fixture.inspect, strings.TrimPrefix(url, "https://")))
	}
	steady := startRuntimeLoadVisitors(t, fixture.visitor.client, urls, payload, rate, onFailure)
	waitUntilIntegrationTime(t, time.Now().Add(duration))
	steadyResults := steady.stop(t, "steady")
	logRuntimeLoadMetrics(t, "steady", metricsBefore, captureRuntimeLoadMetrics(t, fixture))
	logRuntimeLoadResources(t, "steady-after")
	assertRuntimeLoadSuccess(t, "steady", steadyResults)
	for _, stream := range streams {
		select {
		case <-stream.done:
			t.Fatalf("held stream ended before relay stop: %v", stream.err)
		default:
		}
	}

	metricsBefore = captureRuntimeLoadMetrics(t, fixture)
	recovery := startRuntimeLoadVisitors(t, fixture.visitor.client, urls, payload, rate, onFailure)
	waitUntilIntegrationTime(t, time.Now().Add(time.Second))
	failureAt := time.Now()
	stopIntegrationProcess(t, fixture.relayA.process)
	stoppedAt := time.Now()
	fixture.relayA.process = fixture.startRelay(t, fixture.relayA.config)
	waitForProcessReady(t, fixture.relayA.process)
	waitForIntegrationCondition(t, 25*time.Second, func(ctx context.Context) (bool, error) {
		var count int
		err := fixture.inspect.QueryRowContext(ctx, `SELECT count(*) FROM control.route_session_connections c
			JOIN control.relay_leases l ON l.relay_id = c.connected_relay_id AND l.relay_run_id = c.connected_relay_run_id
			AND l.relay_lease_revision = c.connected_relay_lease_revision
			WHERE c.state = 'ready' AND NOT l.draining AND l.lease_expires_at > now()`).Scan(&count)
		return count == routes*2, err
	})
	waitForIngressRoutingCurrent(t, fixture.inspect, 1)
	repairedAt := time.Now()
	repairDuration := time.Since(failureAt)
	waitUntilIntegrationTime(t, failureAt.Add(duration))
	recoveryResults := recovery.stop(t, "relay-restart")
	// The replacement relay has a new registry; never difference its counters
	// against the stopped instance. Other roles retain a complete phase interval.
	delete(metricsBefore, "relay-a")
	metricsAfter := captureRuntimeLoadMetrics(t, fixture)
	delete(metricsAfter, "relay-a")
	logRuntimeLoadMetrics(t, "relay-restart", metricsBefore, metricsAfter)
	var firstByte, firstAfterExit time.Time
	for _, result := range recoveryResults {
		if !result.started.Before(repairedAt) && result.err != nil {
			t.Fatalf("visitor failed after repair and ingress catch-up: %v", result.err)
		}
		if result.err == nil && !result.started.Before(failureAt) && (firstByte.IsZero() || result.firstByte.Before(firstByte)) {
			firstByte = result.firstByte
		}
		if result.err == nil && !result.started.Before(stoppedAt) && (firstAfterExit.IsZero() || result.firstByte.Before(firstAfterExit)) {
			firstAfterExit = result.firstByte
		}
	}
	if firstByte.IsZero() || firstAfterExit.IsZero() {
		t.Fatal("no successful new visitor request after relay stop")
	}
	surviving := 0
	for _, stream := range streams {
		select {
		case <-stream.done:
		default:
			surviving++
		}
		stream.stop(t)
		t.Logf("runtime_held_stream bytes_after_open=%d result=%v", stream.bytes, stream.err)
	}
	t.Logf("runtime_recovery first_new_request_body_byte_after_stop=%s first_new_request_body_byte_after_exit=%s relay_stop_elapsed=%s all_connections_repaired_after_stop=%s held_streams_surviving=%d/%d (one healthy relay remained; stop uses runtime cancellation/drain)", firstByte.Sub(failureAt), firstAfterExit.Sub(stoppedAt), stoppedAt.Sub(failureAt), repairDuration, surviving, len(streams))
	// Every route must serve again, including routes with no sampled request late
	// in the recovery phase. Verify the original route version and certificate.
	for index, url := range urls {
		if result := runtimeLoadRequest(t.Context(), fixture.visitor.client, url, payload); result.err != nil {
			t.Fatalf("route %d after repair: %v", index, result.err)
		}
		assertRouteVersion(t, fixture.inspect, ready[index].RouteID, ready[index].RouteVersion)
	}
	logRuntimeLoadResources(t, "recovery-after")

	closing := routes / 2
	metricsBefore = captureRuntimeLoadMetrics(t, fixture)
	shutdown := startRuntimeLoadVisitors(t, fixture.visitor.client, urls[closing:], payload, rate, onFailure)
	waitUntilIntegrationTime(t, time.Now().Add(time.Second))
	closeAt := time.Now()
	stopRuntimeLoadPublishers(t, handles[:closing])
	t.Logf("runtime_partial_shutdown publishers=%d elapsed=%s", closing, time.Since(closeAt))
	waitUntilIntegrationTime(t, closeAt.Add(duration))
	shutdownResults := shutdown.stop(t, "shutdown-healthy-routes")
	assertRuntimeLoadSuccess(t, "shutdown-healthy-routes", shutdownResults)
	logRuntimeLoadMetrics(t, "shutdown-healthy-routes", metricsBefore, captureRuntimeLoadMetrics(t, fixture))
	closeAt = time.Now()
	stopRuntimeLoadPublishers(t, handles[closing:])
	t.Logf("runtime_final_shutdown publishers=%d elapsed=%s", routes-closing, time.Since(closeAt))
	waitForIntegrationCondition(t, 10*time.Second, func(ctx context.Context) (bool, error) {
		var active int
		err := fixture.inspect.QueryRowContext(ctx, `SELECT
			(SELECT count(*) FROM control.route_sessions WHERE closed_at IS NULL OR assignments_open) +
			(SELECT count(*) FROM control.route_session_connections WHERE state <> 'closed') +
			(SELECT coalesce(sum(assignment_count), 0) FROM control.relay_service_assignment_totals)`).Scan(&active)
		return active == 0, err
	})
	waitForIngressRoutingCurrent(t, fixture.inspect, 1)
	logRuntimeLoadResources(t, "shutdown-after")
	var databaseBytes, routingBytes, reports int64
	if err := fixture.inspect.QueryRowContext(integrationOperationContext(t), `SELECT pg_database_size(current_database()),
		pg_total_relation_size('control.ingress_routing_table_events'), (SELECT count(*) FROM control.ingress_usage_reports)`).Scan(&databaseBytes, &routingBytes, &reports); err != nil {
		t.Fatal(err)
	}
	t.Logf("runtime_verified routes=%d active_sessions=0 active_connections=0 reservations=0 database_bytes=%d routing_bytes=%d real_usage_reports=%d", routes, databaseBytes, routingBytes, reports)
}

type runtimeLoadResult struct {
	started, firstByte time.Time
	duration           time.Duration
	err                error
}

func runtimeLoadRequest(ctx context.Context, client *http.Client, url string, payload []byte) (result runtimeLoadResult) {
	result.started = time.Now()
	defer func() { result.duration = time.Since(result.started) }()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/bytes", nil)
	if err != nil {
		result.err = err
		return
	}
	response, err := client.Do(request)
	if err != nil {
		result.err = err
		return
	}
	defer response.Body.Close()
	first := make([]byte, 1)
	if _, err = io.ReadFull(response.Body, first); err == nil {
		result.firstByte = time.Now()
	}
	rest, readErr := io.ReadAll(io.LimitReader(response.Body, int64(len(payload))+1))
	result.err = errors.Join(err, readErr)
	if result.err == nil && (response.StatusCode != http.StatusOK || !bytes.Equal(append(first, rest...), payload) || response.TLS == nil || len(response.TLS.VerifiedChains) == 0) {
		result.err = fmt.Errorf("visitor response status=%d bytes=%d verified_tls=%t", response.StatusCode, 1+len(rest), response.TLS != nil && len(response.TLS.VerifiedChains) > 0)
	}
	return
}

type runtimeLoadVisitors struct {
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	rows   []runtimeLoadResult
	start  time.Time
	missed int
}

func startRuntimeLoadVisitors(t *testing.T, client *http.Client, urls []string, payload []byte, rate int, onFailure func(string)) *runtimeLoadVisitors {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	load := &runtimeLoadVisitors{cancel: cancel, done: make(chan struct{}), start: time.Now()}
	jobs := make(chan string, 8)
	var workers sync.WaitGroup
	var firstFailure sync.Once
	for range 8 {
		workers.Go(func() {
			for url := range jobs {
				result := runtimeLoadRequest(t.Context(), client, url, payload)
				if result.err != nil {
					firstFailure.Do(func() { onFailure(url) })
				}
				load.mu.Lock()
				load.rows = append(load.rows, result)
				load.mu.Unlock()
			}
		})
	}
	go func() {
		ticker := time.NewTicker(time.Second / time.Duration(rate))
		defer ticker.Stop()
		defer close(load.done)
		index := 0
		offer := func(at time.Time) {
			// Count all elapsed slots; time.Ticker may drop ticks under CPU pressure.
			through := int(at.Sub(load.start) / (time.Second / time.Duration(rate)))
			for ; index < through; index++ {
				select {
				case jobs <- urls[index%len(urls)]:
				default:
					load.missed++
				}
			}
		}
		for {
			select {
			case <-ctx.Done():
				offer(time.Now())
				close(jobs)
				workers.Wait()
				return
			case <-ticker.C:
				offer(time.Now())
			}
		}
	}()
	t.Cleanup(func() { load.stop(t, "cleanup") })
	return load
}

func (l *runtimeLoadVisitors) stop(t *testing.T, phase string) []runtimeLoadResult {
	t.Helper()
	l.cancel()
	if err := waitForDoneWithin(l.done, 15*time.Second); err != nil {
		t.Fatal("visitor workload did not stop: ", err)
	}
	if phase == "cleanup" {
		return nil
	}
	var durations []time.Duration
	var firstBytes []time.Duration
	failures := 0
	for _, row := range l.rows {
		if row.err != nil {
			if failures < 3 {
				t.Logf("runtime_phase=%s request_started_elapsed=%s visitor_error=%v", phase, row.started.Sub(l.start), row.err)
			}
			failures++
			continue
		}
		durations = append(durations, row.duration)
		firstBytes = append(firstBytes, row.firstByte.Sub(row.started))
	}
	slices.Sort(durations)
	slices.Sort(firstBytes)
	t.Logf("runtime_phase=%s elapsed=%s requests=%d success=%d failures=%d missed=%d success_total_p50=%s success_total_p95=%s success_total_max=%s success_body_first_byte_p95=%s", phase, time.Since(l.start), len(l.rows), len(durations), failures, l.missed,
		runtimeLoadQuantile(durations, .5), runtimeLoadQuantile(durations, .95), runtimeLoadQuantile(durations, 1), runtimeLoadQuantile(firstBytes, .95))
	if l.missed != 0 {
		t.Errorf("runtime phase %s missed %d offered requests", phase, l.missed)
	}
	return l.rows
}

func assertRuntimeLoadSuccess(t *testing.T, phase string, results []runtimeLoadResult) {
	t.Helper()
	if len(results) == 0 {
		t.Fatal("no visitor requests in ", phase)
	}
	for _, result := range results {
		if result.err != nil {
			t.Fatalf("visitor failed in %s: %v", phase, result.err)
		}
	}
}

func runtimeLoadQuantile(values []time.Duration, fraction float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	return values[int(float64(len(values)-1)*fraction)]
}

func stopRuntimeLoadPublishers(t *testing.T, publishers []*integrationPublisher) {
	t.Helper()
	results := make(chan error, len(publishers))
	var workers sync.WaitGroup
	started := time.Now()
	for worker := range min(4, len(publishers)) {
		workers.Go(func() {
			for index := worker; index < len(publishers); index += 4 {
				p := publishers[index]
				p.cancel()
				err := waitForDoneWithin(p.done, 10*time.Second)
				if err == nil && !runtimeLoadCancellationOnly(p.result()) {
					err = p.result()
				}
				results <- err
			}
		})
	}
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("publisher shutdown after %s: %v", time.Since(started), err)
		}
	}
}

func runtimeLoadCancellationOnly(err error) bool {
	if err == nil || err == context.Canceled {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if !runtimeLoadCancellationOnly(child) {
				return false
			}
		}
		return len(joined.Unwrap()) != 0
	}
	return errors.Unwrap(err) != nil && runtimeLoadCancellationOnly(errors.Unwrap(err))
}

func TestRuntimeLoadCancellationDoesNotHideCloseFailure(t *testing.T) {
	closeFailure := errors.New("close failed")
	for _, test := range []struct {
		err  error
		want bool
	}{
		{nil, true}, {context.Canceled, true}, {fmt.Errorf("wrapped: %w", context.Canceled), true},
		{errors.Join(context.Canceled, context.Canceled), true},
		{closeFailure, false}, {context.DeadlineExceeded, false},
		{errors.Join(context.Canceled, closeFailure), false},
	} {
		if got := runtimeLoadCancellationOnly(test.err); got != test.want {
			t.Errorf("cancellationOnly(%v)=%t, want %t", test.err, got, test.want)
		}
	}
}

type runtimeLoadStream struct {
	cancel context.CancelFunc
	done   chan struct{}
	err    error
	bytes  int64
}

func startRuntimeLoadStream(t *testing.T, transport http.RoundTripper, url string) *runtimeLoadStream {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	stream := &runtimeLoadStream{cancel: cancel, done: make(chan struct{})}
	timer := time.AfterFunc(5*time.Second, cancel)
	defer timer.Stop()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/stream", nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	reader := bufio.NewReader(response.Body)
	first, err := reader.ReadString('\n')
	timer.Stop()
	if err != nil || response.StatusCode != http.StatusOK || first != "ready\n" {
		cancel()
		_ = response.Body.Close()
		t.Fatalf("held stream opening: status=%d first=%q: %v", response.StatusCode, first, err)
	}
	go func() {
		defer close(stream.done)
		defer response.Body.Close()
		stream.bytes, stream.err = io.Copy(io.Discard, reader)
	}()
	t.Cleanup(func() { stream.stop(t) })
	return stream
}

func (s *runtimeLoadStream) stop(t *testing.T) {
	t.Helper()
	s.cancel()
	if err := waitForDoneWithin(s.done, 5*time.Second); err != nil {
		t.Error("held stream did not stop: ", err)
	}
}

func runtimeLoadInt(t *testing.T, name string, fallback, minimum, maximum int) int {
	t.Helper()
	if raw := os.Getenv(name); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < minimum || value > maximum {
			t.Fatalf("%s must be between %d and %d", name, minimum, maximum)
		}
		return value
	}
	return fallback
}

func logRuntimeLoadResources(t *testing.T, phase string) {
	t.Helper()
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	t.Logf("runtime_resources phase=%s go_heap_inuse=%d go_sys=%d goroutines=%d", phase, memory.HeapInuse, memory.Sys, runtime.NumGoroutine())
	for _, name := range []string{"cpu.max", "cpu.stat", "memory.max", "memory.current", "memory.peak", "memory.events"} {
		data, err := os.ReadFile("/sys/fs/cgroup/" + name)
		if err == nil {
			t.Logf("runtime_cgroup phase=%s %s=%s", phase, name, strings.Join(strings.Fields(string(data)), " "))
		}
	}
}

func captureRuntimeLoadMetrics(t *testing.T, fixture *splitPublishFixture) map[string][]*dto.MetricFamily {
	t.Helper()
	result := make(map[string][]*dto.MetricFamily)
	for role, process := range map[string]*integrationProcess{"control": fixture.control, "ingress": fixture.ingress, "relay-a": fixture.relayA.process, "relay-b": fixture.relayB.process} {
		response, err := integrationGET(integrationOperationContext(t), &http.Client{Timeout: 5 * time.Second}, "http://"+process.metricsAddress+"/metrics")
		if err != nil {
			t.Fatal(err)
		}
		families, err := observability.ParseMetrics(response.Body)
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("runtime metrics role=%s status=%d: %v", role, response.StatusCode, errors.Join(err, closeErr))
		}
		result[role] = families
	}
	return result
}

func logRuntimeLoadMetrics(t *testing.T, phase string, before, after map[string][]*dto.MetricFamily) {
	t.Helper()
	for _, role := range []string{"control", "ingress", "relay-a", "relay-b"} {
		if before[role] == nil || after[role] == nil {
			continue
		}
		summaries, err := observability.DurationSummaries(before[role], after[role])
		if err != nil {
			t.Fatalf("runtime metrics phase=%s role=%s: %v", phase, role, err)
		}
		for _, summary := range summaries {
			if summary.Name == "tnl_operation_duration_seconds" && summary.Count != 0 {
				t.Logf("runtime_operation phase=%s role=%s labels=%v calls=%d mean_seconds=%g", phase, role, summary.Labels, summary.Count, summary.MeanSeconds)
			}
		}
		for _, family := range after[role] {
			switch family.GetName() {
			case "tnl_capacity_rejections_total", "tnl_source_limiter_rejections_total", "tnl_ip_allowlist_denials_total":
				for _, metric := range family.Metric {
					t.Logf("runtime_rejections phase=%s role=%s metric=%s labels=%v cumulative=%g", phase, role, family.GetName(), metric.Label, metric.GetCounter().GetValue())
				}
			}
		}
		// Every role registry observes this same Go process; report process CPU
		// once, never add these duplicated process collectors across roles.
		if role == "control" {
			for _, name := range []string{"process_cpu_seconds_total", "process_resident_memory_bytes", "tnl_database_pool_canceled_acquires_total"} {
				read := func(families []*dto.MetricFamily) float64 {
					for _, family := range families {
						if family.GetName() == name && len(family.Metric) == 1 {
							if family.Metric[0].Counter != nil {
								return family.Metric[0].Counter.GetValue()
							}
							return family.Metric[0].GetGauge().GetValue()
						}
					}
					return -1
				}
				t.Logf("runtime_process phase=%s metric=%s before=%g after=%g", phase, name, read(before[role]), read(after[role]))
			}
		}
	}
}

func runtimeLoadPublisherDiagnostics(database *sql.DB, hostname string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var result string
	err := database.QueryRowContext(ctx, `SELECT jsonb_build_object(
		'now', now(),
		'hostname', r.canonical_hostname, 'route_version', s.route_version, 'session_state', s.state,
		'last_heartbeat_at', s.last_heartbeat_at,
		'publisher_expires_at', s.publisher_expires_at, 'certificate_installed_at', s.certificate_installed_at,
		'order_state', o.state, 'order_updated_at', o.updated_at, 'attempts', o.attempts,
		'work_owner', o.work_owner, 'work_expires_at', o.work_expires_at, 'last_error', o.last_error,
		'authorizations', (SELECT jsonb_agg(jsonb_build_object('state', a.state, 'revision', a.authorization_revision, 'updated_at', a.updated_at))
			FROM control.acme_authorizations a WHERE a.order_id = o.id),
		'connections', (SELECT jsonb_agg(jsonb_build_object('slot', c.connection_slot, 'state', c.state, 'relay_run_id', c.connected_relay_run_id))
			FROM control.route_session_connections c WHERE c.route_session_id = s.id),
		'routing_revision', (SELECT current_revision FROM control.ingress_routing_table_clock),
		'latest_projection', (SELECT convert_from(e.projection, 'UTF8')::jsonb FROM control.ingress_routing_table_events e
			WHERE e.route_id = r.id AND e.route_version = s.route_version AND e.event_kind IN ('route_upsert', 'route_tombstone') ORDER BY e.routing_table_revision DESC LIMIT 1),
		'relays', (SELECT jsonb_agg(jsonb_build_object('id', l.relay_id, 'run', l.relay_run_id, 'expiry', l.lease_expires_at, 'draining', l.draining)) FROM control.relay_leases l),
		'ingresses', (SELECT jsonb_agg(jsonb_build_object('applied_revision', i.routing_table_revision, 'lease_expires_at', i.lease_expires_at)) FROM control.ingress_leases i)
	)::text FROM control.routes r JOIN control.route_sessions s ON s.route_id = r.id
	LEFT JOIN control.acme_orders o ON o.route_session_id = s.id
	WHERE r.canonical_hostname = $1 ORDER BY s.route_version DESC, o.created_at DESC LIMIT 1`, hostname).Scan(&result)
	var formatted bytes.Buffer
	if err == nil && json.Indent(&formatted, []byte(result), "", "  ") == nil {
		result = formatted.String()
	}
	return fmt.Sprintf("; publisher state=%s diagnostic_error=%v", result, err)
}
