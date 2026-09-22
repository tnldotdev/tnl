package tnldruntime

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/tnldotdev/tnl/internal/benchworkload"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/testutil"
)

type separatedSnapshot struct {
	Resources map[string]separatedResources
	Metrics   map[string][]*dto.MetricFamily `json:"-"`
}

var (
	runtimeLoadRoutes             = flag.Int("tnl-runtime-load-routes", 4, "runtime load route count")
	runtimeLoadStartParallel      = flag.Int("tnl-runtime-load-start-parallel", 4, "maximum concurrently activating publishers (1-1000)")
	runtimeLoadReadyTimeout       = flag.Duration("tnl-runtime-load-ready-timeout", 30*time.Second, "publisher readiness timeout (30s-5m)")
	runtimeLoadCertificateWorkers = flag.Int("tnl-runtime-load-route-certificate-workers", 4, "route certificate workers per control process (1-8)")
	runtimeLoadRPS                = flag.Int("tnl-runtime-load-rps", 16, "runtime load offered requests/second")
	runtimeLoadDuration           = flag.Duration("tnl-runtime-load-duration", 10*time.Second, "runtime measurement window")
	runtimeLoadWorkers            = flag.Int("tnl-runtime-load-workers", 128, "total visitor concurrency across four containers")
	runtimeLoadQueue              = flag.Int("tnl-runtime-load-queue", 8, "total waiting slots across four containers")
	runtimeLoadScenario           = flag.String("tnl-runtime-load-scenario", "relay-restart", "relay-restart, relay-kill, forwarding-blackhole, publisher-blackhole, udp-fallback, latency, or packet-loss")
	runtimeLoadNetworkPath        = flag.String("tnl-runtime-load-network-path", "forwarding", "forwarding or publisher impairment path")
	runtimeLoadRTT                = flag.Duration("tnl-runtime-load-rtt", 20*time.Millisecond, "added round-trip latency")
	runtimeLoadLoss               = flag.Float64("tnl-runtime-load-loss", 0.1, "packet loss percent in each direction")
	runtimeLoadTrace              = flag.Bool("tnl-runtime-load-trace", false, "trace certificate provisioning")
)

func TestLoadSeparatedRuntime(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierRuntimeLoad)
	if *separatedComponent != "coordinator" {
		t.Skip("run task go:test:load:runtime")
	}
	routes, rate, duration := separatedLoadParameters(t)
	recordSeparatedAdmission(t, nil)
	token, err := os.ReadFile("/load/coordinator-token")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: benchworkload.NewCoordinator().Handler(string(token))}
	serverDone := make(chan struct{})
	go func() { defer close(serverDone); _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); <-serverDone })
	separatedWrite(t, "coordinator.ready", true)
	database := inspectStandaloneTestDatabase(t, testutil.PostgresURL(t))
	t.Logf("separated_load routes=%d rps=%d sources=4 workers=%d queue=%d payload=32768 phase_duration=%s", routes, rate, *runtimeLoadWorkers, *runtimeLoadQueue, duration)
	defer func() {
		if !t.Failed() {
			return
		}
		var states string
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err := database.QueryRowContext(ctx, `SELECT jsonb_build_object('sessions',
			(SELECT jsonb_agg(jsonb_build_object('state', state, 'route_id', route_id, 'version', route_version, 'expires_at', publisher_expires_at)) FROM control.route_sessions),
			'orders', (SELECT jsonb_agg(jsonb_build_object('state', state, 'route_id', route_id, 'attempts', attempts, 'available_at', available_at, 'claimed', work_owner IS NOT NULL, 'last_error', last_error)) FROM control.acme_orders))::text`).Scan(&states)
		t.Logf("separated_failure_state=%s error=%v", states, err)
	}()
	for _, name := range []string{"control", "ingress", "relay-a", "relay-b", "app", "pebble"} {
		separatedWait(t, name+".ready", 30*time.Second, nil)
	}
	verifySeparatedAdmission(t)
	var initialFault separatedRestart
	if runtimeEarlyFault(*runtimeLoadScenario) {
		separatedWrite(t, "fault.request", *runtimeLoadScenario)
		separatedWait(t, "fault.applied", 15*time.Second, &initialFault)
		t.Logf("network_impairment scenario=%s path=%s added_rtt=%s loss_percent=%g active_before_publishing=true", *runtimeLoadScenario, *runtimeLoadNetworkPath, *runtimeLoadRTT, *runtimeLoadLoss)
	}
	for _, component := range separatedComponents {
		separatedWait(t, component+".resources-ready", 30*time.Second, nil)
	}
	activationBefore := separatedCapture(t, database, "activation-before")
	activation := time.Now()
	stopTrace := func() {}
	if *runtimeLoadTrace {
		stopTrace = traceRuntimeCertificateState(t, database, activation)
	}
	defer stopTrace()
	separatedWrite(t, "publish.start", activation)
	var publishers separatedPublishers
	// Each publisher retains its own readiness deadline, starting at launch.
	parallel := min(routes, *runtimeLoadStartParallel)
	waves := (routes + parallel - 1) / parallel
	separatedWait(t, "publishers.ready", time.Duration(waves)*(*runtimeLoadReadyTimeout)+10*time.Second, &publishers)
	stopTrace()
	if len(publishers.Ready) != routes {
		t.Fatal("publisher count mismatch")
	}
	if *runtimeLoadScenario == "udp-fallback" && publishers.Fallbacks != int64(routes) {
		t.Fatalf("fallback events=%d want=%d", publishers.Fallbacks, routes)
	}
	if *runtimeLoadScenario == "udp-fallback" {
		separatedWait(t, "udp.cleaned", 15*time.Second, nil)
	}
	for _, ready := range publishers.Ready {
		waitForReadyPublisherConnections(t, database, ready.RouteID, ready.RouteVersion, 2)
	}
	waitForIngressRoutingCurrent(t, database, 1)
	var orders, installed, distinctRoutes int
	var workerAttempts int64
	if err := database.QueryRowContext(integrationOperationContext(t), `SELECT count(*), count(*) FILTER (WHERE state = 'installed'), count(DISTINCT route_id), coalesce(sum(attempts), 0) FROM control.acme_orders`).Scan(&orders, &installed, &distinctRoutes, &workerAttempts); err != nil {
		t.Fatal(err)
	}
	caOrders := separatedResource(t, "control").CAOrders
	activationElapsed := time.Since(activation)
	durations := slices.Sorted(slices.Values(publishers.Activation))
	if len(durations) != routes {
		t.Fatal("incomplete activation timings")
	}
	t.Logf("separated_activation_summary routes=%d parallel=%d min=%s p50=%s p95=%s max=%s publishers_ready=%s verified=%s",
		routes, parallel, durations[0], durations[(routes-1)/2], durations[(95*routes+99)/100-1], durations[routes-1], publishers.ActivationDuration, activationElapsed)
	separatedArtifact(t, "activation", map[string]any{"parallel": parallel, "certificate_workers": *runtimeLoadCertificateWorkers, "launch_to_ready": durations,
		"publishers_ready": publishers.ActivationDuration, "verified": activationElapsed, "ca_orders": caOrders, "certificate_work_attempts": workerAttempts})
	separatedReportResources(t, "activation", activationBefore, separatedCapture(t, database, "activation-after"))
	if orders != routes || installed != routes || distinctRoutes != routes || caOrders != int64(routes) {
		t.Fatalf("duplicate/incomplete issuance: routes=%d orders=%d installed=%d distinct=%d CA=%d", routes, orders, installed, distinctRoutes, caOrders)
	}
	t.Logf("separated_activation_verified routes=%d installed=%d CA_new_orders=%d elapsed=%s", routes, installed, caOrders, activationElapsed)
	separatedWrite(t, "visitors.start", time.Now())
	for i := 1; i <= 4; i++ {
		separatedWait(t, fmt.Sprintf("visitor-%d.ready", i), 15*time.Second, nil)
	}
	sequence := 0
	for _, phase := range []string{"steady", *runtimeLoadScenario, "shutdown"} {
		before := separatedCapture(t, database, phase+"-before")
		stopSamples := sampleSeparatedGauges(t, phase)
		start := time.Now().Add(time.Second)
		var restart separatedRestart
		var repaired time.Time
		window := duration
		if phase == "relay-restart" {
			window = max(window, 40*time.Second)
		}
		if phase == "relay-kill" {
			window = max(window, 80*time.Second)
		}
		if runtimeBlackhole(phase) {
			window = max(window, 50*time.Second)
			if phase == "publisher-blackhole" {
				window = max(window, 80*time.Second)
			}
			separatedWrite(t, "fault.request", phase)
			separatedWait(t, "fault.applied", 15*time.Second, &restart)
			// These held streams are opened through the healthy path while the
			// drop is installed, before the measured offer window begins.
			separatedProbe(t, &sequence, benchworkload.Phase{Name: phase + "-healthy-held", URLs: publishers.URLs, OpenHeld: true})
			start = time.Now().Add(time.Second)
		}
		if phase == *runtimeLoadScenario && runtimeEarlyFault(phase) {
			restart = initialFault
		}
		urls := publishers.URLs
		if phase == "shutdown" {
			urls = urls[len(urls)/2:]
		}
		separatedWrite(t, fmt.Sprintf("phase-%d", sequence), benchworkload.Phase{Name: phase, Start: start, Duration: window, URLs: urls, CloseHeld: phase == *runtimeLoadScenario && !runtimeEarlyFault(phase)})
		sequence++
		waitUntilIntegrationTime(t, start.Add(time.Second))
		if phase == "publisher-blackhole" {
			waitForIntegrationCondition(t, 65*time.Second, func(ctx context.Context) (bool, error) {
				var count int
				err := database.QueryRowContext(ctx, `SELECT count(*) FROM control.route_session_connections WHERE connected_relay_id='relay-a-1' AND state='ready'`).Scan(&count)
				return count == 0, err
			})
			t.Logf("publisher_connection_loss_detected elapsed_since_drop=%s", time.Since(restart.Exited))
		}
		if phase == "relay-kill" {
			var oldRun string
			if err := database.QueryRowContext(integrationOperationContext(t), `SELECT relay_run_id FROM control.relay_leases WHERE relay_id = 'relay-a-1'`).Scan(&oldRun); err != nil {
				t.Fatal(err)
			}
			separatedWrite(t, "fault.request", phase)
			separatedWait(t, "fault.applied", 15*time.Second, &restart)
			var restored time.Time
			separatedWait(t, "fault.restored", 45*time.Second, &restored)
			restart.Restored = restored
			separatedWait(t, "relay-a.restarted", 10*time.Second, nil)
			waitForIntegrationCondition(t, 25*time.Second, func(ctx context.Context) (bool, error) {
				var current string
				err := database.QueryRowContext(ctx, `SELECT relay_run_id FROM control.relay_leases WHERE relay_id='relay-a-1' AND lease_expires_at>now() AND NOT draining`).Scan(&current)
				return current != "" && current != oldRun, err
			})
			repaired = separatedWaitForRecovery(t, database, publishers)
		}
		switch phase {
		case "relay-restart":
			separatedWrite(t, "relay-a.restart", time.Now())
			separatedWait(t, "relay-a.stopped", 10*time.Second, &restart)
			separatedWait(t, "relay-a.restarted", 10*time.Second, nil)
			repaired = separatedWaitForRecovery(t, database, publishers)
		case "shutdown":
			separatedWrite(t, "close-half", time.Now())
			var elapsed time.Duration
			separatedWait(t, "close-half.done", time.Duration((routes/2+3)/4)*10*time.Second, &elapsed)
			t.Logf("separated_partial_shutdown publishers=%d elapsed=%s", routes/2, elapsed)
		}
		waitUntilIntegrationTime(t, start.Add(window))
		var results []separatedVisitorResult
		for i := 1; i <= 4; i++ {
			var result separatedVisitorResult
			separatedWait(t, fmt.Sprintf("%s.visitor-%d", phase, i), 15*time.Second, &result)
			results = append(results, result)
		}
		stopSamples()
		data, err := json.Marshal(results)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join("/results", phase+"-visitors.json"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		after := separatedCapture(t, database, phase+"-after")
		separatedReportResources(t, phase, before, after)
		if !runtimeControlledFault(phase) {
			separatedReportVisitors(t, phase, results, restart, repaired)
		}
		if phase == "steady" && runtimeBlackhole(*runtimeLoadScenario) {
			assertRelayOpenedVisitors(t, before, after, "relay-a")
		}
		// Cover every live route, not only routes sampled late in a traffic window.
		separatedProbe(t, &sequence, benchworkload.Phase{Name: phase + "-correctness", URLs: urls})
		if runtimeControlledFault(phase) {
			if runtimeBlackhole(phase) {
				assertRelayOpenedVisitors(t, before, after, "relay-b")
			}
			separatedWrite(t, "fault.release", true)
			separatedWait(t, "fault.restored", 15*time.Second, &restart.Restored)
			repaired = separatedWaitForRecovery(t, database, publishers)
			separatedProbe(t, &sequence, benchworkload.Phase{Name: phase + "-restored", URLs: publishers.URLs, CloseHeld: true})
			separatedReportVisitors(t, phase, results, restart, repaired)
		}
	}
	separatedWrite(t, fmt.Sprintf("phase-%d", sequence), benchworkload.Phase{Done: true})
	for i := 1; i <= 4; i++ {
		var passed bool
		separatedWait(t, fmt.Sprintf("visitor-%d.done", i), 30*time.Second, &passed)
		if !passed {
			t.Errorf("visitor-%d reported workload failures", i)
		}
	}
	separatedWrite(t, "close-all", time.Now())
	var elapsed time.Duration
	separatedWait(t, "close-all.done", time.Duration(((routes+1)/2+3)/4)*10*time.Second, &elapsed)
	t.Logf("separated_final_shutdown publishers=%d elapsed=%s", (routes+1)/2, elapsed)
	waitForIntegrationCondition(t, 10*time.Second, func(ctx context.Context) (bool, error) {
		var active int
		err := database.QueryRowContext(ctx, `SELECT
			(SELECT count(*) FROM control.route_sessions WHERE closed_at IS NULL OR assignments_open) +
			(SELECT count(*) FROM control.route_session_connections WHERE state <> 'closed') +
			(SELECT coalesce(sum(assignment_count), 0) FROM control.relay_service_assignment_totals)`).Scan(&active)
		return active == 0, err
	})
	waitForIngressRoutingCurrent(t, database, 1)
	separatedCapture(t, database, "final")
	if got := separatedResource(t, "control").CAOrders; got != int64(routes) {
		t.Errorf("certificate issuance changed during workload: got %d want %d", got, routes)
	}
	// Stop ingress while control and PostgreSQL remain available. Its production
	// reporter flushes final checkpoints and marks this process run complete.
	separatedWrite(t, "ingress.stop", time.Now())
	separatedWait(t, "ingress.stopped", 10*time.Second, nil)
	var buckets, coveredRoutes, attempts, successes, ingressBytes, egressBytes int64
	if err := database.QueryRowContext(integrationOperationContext(t), `SELECT count(*), count(DISTINCT route_id), coalesce(sum(connection_attempts),0),
		coalesce(sum(successful_streams),0), coalesce(sum(ingress_bytes),0), coalesce(sum(egress_bytes),0) FROM control.route_usage_buckets`).Scan(&buckets, &coveredRoutes, &attempts, &successes, &ingressBytes, &egressBytes); err != nil {
		t.Fatal(err)
	}
	if coveredRoutes != int64(routes) || successes == 0 || egressBytes == 0 {
		t.Error("real visitor usage was not persisted")
	}
	var incomplete, mismatches int
	if err := database.QueryRowContext(integrationOperationContext(t), `SELECT count(*) FROM control.ingress_usage_runs WHERE NOT coverage_complete`).Scan(&incomplete); err != nil || incomplete != 0 {
		t.Fatalf("ingress usage completion: incomplete=%d error=%v", incomplete, err)
	}
	if err := database.QueryRowContext(integrationOperationContext(t), `WITH latest AS (
		SELECT DISTINCT ON (ingress_id, ingress_run_id, route_id, route_version, bucket_start) *
		FROM control.ingress_usage_reports ORDER BY ingress_id, ingress_run_id, route_id, route_version, bucket_start, report_revision DESC
	), totals AS (
		SELECT route_id, route_version, bucket_start, sum(connection_attempts) AS attempts,
		sum(successful_streams) AS successes, sum(ingress_bytes) AS ingress_bytes, sum(egress_bytes) AS egress_bytes
		FROM latest GROUP BY route_id, route_version, bucket_start
	) SELECT count(*) FROM totals t FULL JOIN control.route_usage_buckets b USING (route_id, route_version, bucket_start)
	WHERE t.attempts IS DISTINCT FROM b.connection_attempts OR t.successes IS DISTINCT FROM b.successful_streams
	OR t.ingress_bytes IS DISTINCT FROM b.ingress_bytes OR t.egress_bytes IS DISTINCT FROM b.egress_bytes`).Scan(&mismatches); err != nil || mismatches != 0 {
		t.Fatalf("final usage accounting: mismatches=%d error=%v", mismatches, err)
	}
	t.Logf("separated_verified routes=%d active_sessions=0 active_connections=0 reservations=0 usage_buckets=%d attempts=%d successes=%d ingress_bytes=%d egress_bytes=%d", routes, buckets, attempts, successes, ingressBytes, egressBytes)
}

func separatedLoadParameters(t *testing.T) (int, int, time.Duration) {
	t.Helper()
	// Validate admission inputs with the production configuration rules before
	// any component starts work, including the coordinator and visitors.
	separatedConfig(t, "ingress")
	routes, rate, duration := *runtimeLoadRoutes, *runtimeLoadRPS, *runtimeLoadDuration
	if routes < 4 || routes > 1000 {
		t.Fatal("separated runtime load routes must be between 4 and 1000")
	}
	if *runtimeLoadStartParallel < 1 || *runtimeLoadStartParallel > 1000 {
		t.Fatal("publisher startup concurrency must be between 1 and 1000")
	}
	if *runtimeLoadReadyTimeout < 30*time.Second || *runtimeLoadReadyTimeout > 5*time.Minute {
		t.Fatal("publisher readiness timeout must be between 30s and 5m")
	}
	if *runtimeLoadCertificateWorkers < 1 || *runtimeLoadCertificateWorkers > 8 {
		t.Fatal("route certificate workers must be between 1 and 8")
	}
	if rate < 4 || rate > 500 {
		t.Fatal("separated runtime load requests per second must be between 4 and 500")
	}
	if duration < 10*time.Second || duration > 2*time.Minute {
		t.Fatal("separated runtime load phase duration must be between 10s and 2m")
	}
	if *runtimeLoadWorkers < 4 || *runtimeLoadWorkers > 4096 || *runtimeLoadQueue < 0 || *runtimeLoadQueue > 4096 {
		t.Fatal("invalid visitor concurrency or queue")
	}
	if !slices.Contains([]string{"relay-restart", "relay-kill", "forwarding-blackhole", "publisher-blackhole", "udp-fallback", "latency", "packet-loss"}, *runtimeLoadScenario) {
		t.Fatal("invalid runtime scenario")
	}
	if !slices.Contains([]string{"forwarding", "publisher"}, *runtimeLoadNetworkPath) {
		t.Fatal("invalid network path")
	}
	if *runtimeLoadScenario == "latency" && !slices.Contains([]time.Duration{20 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond}, *runtimeLoadRTT) {
		t.Fatal("invalid RTT")
	}
	if *runtimeLoadScenario == "packet-loss" && *runtimeLoadLoss != 0.1 && *runtimeLoadLoss != 1 {
		t.Fatal("invalid packet loss")
	}
	return routes, rate, duration
}

func separatedCapture(t *testing.T, database *sql.DB, name string) separatedSnapshot {
	t.Helper()
	result := separatedSnapshot{Resources: make(map[string]separatedResources), Metrics: make(map[string][]*dto.MetricFamily)}
	coordinator, err := readSeparatedResources()
	if err != nil {
		t.Fatal(err)
	}
	coordinator.NetworkNamespace = "coordinator"
	result.Resources["coordinator"] = coordinator
	for _, component := range separatedComponents {
		result.Resources[component] = separatedResource(t, component)
	}
	// Read the PostgreSQL process's own cgroup/proc files through the disposable
	// superuser connection, avoiding a metrics sidecar in its memory budget.
	postgres, err := readSeparatedResourceFiles(func(path string) (string, error) {
		var text string
		err := database.QueryRowContext(integrationOperationContext(t), `SELECT pg_read_file($1, 0, 65536)`, path).Scan(&text)
		return strings.TrimSpace(text), err
	})
	if err != nil {
		t.Fatal(err)
	}
	postgres.NetworkNamespace = "postgres"
	result.Resources["postgres"] = postgres
	for _, role := range []string{"control", "ingress", "relay-a", "relay-b"} {
		response, err := integrationGET(integrationOperationContext(t), &http.Client{Timeout: 2 * time.Second}, "http://"+role+":9090/metrics")
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("metrics %s: %v status=%d", role, err, response.StatusCode)
		}
		if err := os.WriteFile(filepath.Join("/results", name+"-"+role+".prom"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		families, err := observability.ParseMetrics(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		result.Metrics[role] = families
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("/results", name+".json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return result
}

func separatedReportResources(t *testing.T, phase string, before, after separatedSnapshot) {
	t.Helper()
	for _, component := range append(slices.Clone(separatedComponents), "postgres", "coordinator") {
		a, b := before.Resources[component], after.Resources[component]
		if a.ProcessRunID != b.ProcessRunID {
			t.Logf("separated_resource phase=%s component=%s interval_reset=true before_run=%s after_run=%s memory=%d peak=%d oom_kills=%d", phase, component, a.ProcessRunID, b.ProcessRunID, b.Memory, b.Peak, b.OOMKills)
			if b.OOMKills != 0 {
				t.Errorf("%s OOM after restart", component)
			}
			continue
		}
		seconds := b.At.Sub(a.At).Seconds()
		t.Logf("separated_resource phase=%s component=%s interval=%.3fs quota=%q memory_limit=%q cpu_seconds=%.6f cpu_cores=%.4f throttled_seconds=%.6f throttled_periods=%d/%d memory=%d peak=%d oom_kills=%d rx_bytes=%d tx_bytes=%d gomaxprocs=%d network_namespace=%s",
			phase, component, seconds, b.CPUQuota, b.MemoryLimit, float64(b.CPUUsec-a.CPUUsec)/1e6, float64(b.CPUUsec-a.CPUUsec)/1e6/seconds,
			float64(b.ThrottledUsec-a.ThrottledUsec)/1e6, b.ThrottledPeriods-a.ThrottledPeriods, b.Periods-a.Periods, b.Memory, b.Peak, b.OOMKills-a.OOMKills,
			b.ReceiveBytes-a.ReceiveBytes, b.SendBytes-a.SendBytes, b.GOMAXPROCS, b.NetworkNamespace)
		if b.OOMKills > a.OOMKills {
			t.Errorf("%s OOM in %s", component, phase)
		}
	}
	for _, role := range []string{"control", "ingress", "relay-a", "relay-b"} {
		if role == "relay-a" && (phase == "relay-restart" || phase == "relay-kill") {
			continue
		} // New runtime registry.
		summaries, err := observability.DurationSummaries(before.Metrics[role], after.Metrics[role])
		if err != nil {
			t.Fatal(err)
		}
		for _, summary := range summaries {
			if summary.Count > 0 && summary.Name != "tnl_database_query_duration_seconds" {
				t.Logf("separated_duration phase=%s role=%s metric=%s labels=%v calls=%d mean_seconds=%g", phase, role, summary.Name, summary.Labels, summary.Count, summary.MeanSeconds)
			}
		}
	}
}

func separatedReportVisitors(t *testing.T, phase string, results []separatedVisitorResult, restart separatedRestart, repaired time.Time) {
	t.Helper()
	var first, firstExit time.Time
	failures, missed, total, surviving := 0, 0, 0, 0
	var merged benchworkload.VisitorResult
	cohorts := make(map[string]benchworkload.VisitorResult)
	healthy, progressing := 0, 0
	for _, result := range results {
		healthy += result.HealthyHeld
		progressing += result.HealthyHeldProgress
		for name, summary := range result.Cohorts {
			cohort := cohorts[name]
			if err := cohort.Merge(summary); err != nil {
				t.Fatal(err)
			}
			cohorts[name] = cohort
		}
		if err := merged.Merge(result.VisitorResult); err != nil {
			t.Fatal(err)
		}
		missed += result.Missed + result.QueueExpired
		surviving += result.HeldSurviving
		for _, row := range result.Requests {
			total++
			if row.Error != "" {
				failures++
				if failures <= 3 {
					t.Logf("separated_request_failure phase=%s started=%s error=%s", phase, row.Started, row.Error)
				}
				if runtimeControlledFault(phase) || phase != *runtimeLoadScenario || !row.Started.Before(repaired) {
					t.Errorf("visitor failed in %s after recovery=%t", phase, !row.Started.Before(repaired))
				}
				continue
			}
			if !row.Started.Before(restart.Started) && (first.IsZero() || row.FirstByte.Before(first)) {
				first = row.FirstByte
			}
			if !row.Started.Before(restart.Exited) && (firstExit.IsZero() || row.FirstByte.Before(firstExit)) {
				firstExit = row.FirstByte
			}
		}
	}
	format := func(value *float64) string {
		if value == nil {
			return "unavailable"
		}
		return fmt.Sprintf("%.3fms", *value)
	}
	t.Logf("separated_visitors phase=%s requests=%d success=%d failures=%d missed=%d p50=%s p95=%s maximum=%.3fms first_body_byte_p95=%s offer=%s drain=%s", phase, total, merged.Successes, failures, missed,
		format(merged.Total.Percentile(50)), format(merged.Total.Percentile(95)), merged.Total.MaximumMilliseconds, format(merged.FirstByte.Percentile(95)), merged.OfferDuration, merged.DrainDuration)
	if data, err := json.Marshal(merged); err != nil {
		t.Fatal(err)
	} else if err := os.WriteFile(filepath.Join("/results", phase+"-summary.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if missed != 0 || total == 0 {
		t.Errorf("phase %s: missed=%d requests=%d", phase, missed, total)
	}
	if data, err := json.Marshal(cohorts); err != nil {
		t.Fatal(err)
	} else if err := os.WriteFile(filepath.Join("/results", phase+"-cohorts.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if runtimeBlackhole(phase) {
		t.Logf("healthy_held_streams alive=%d progressing=%d", healthy, progressing)
		if healthy == 0 || progressing != healthy {
			t.Error("healthy-path held streams did not survive")
		}
	}
	if phase == *runtimeLoadScenario {
		if first.IsZero() || firstExit.IsZero() {
			t.Error("no successful visitor during recovery")
		}
		if phase == "forwarding-blackhole" {
			t.Logf("separated_recovery first_body_after_drop_applied=%s verified_recovery_after_rule_removal=%s held_surviving=%d", firstExit.Sub(restart.Exited), repaired.Sub(restart.Restored), surviving)
		} else {
			t.Logf("separated_recovery first_body_after_stop=%s first_body_after_exit=%s runtime_exit=%s all_connections_repaired=%s held_surviving=%d", first.Sub(restart.Started), firstExit.Sub(restart.Exited), restart.Exited.Sub(restart.Started), repaired.Sub(restart.Started), surviving)
		}
		data, err := json.Marshal(struct {
			Scenario                                          string
			Fault                                             separatedRestart
			FirstSuccessfulBodyAfterApplied, VerifiedRecovery time.Time
			HeldSurviving                                     int
		}{phase, restart, firstExit, repaired, surviving})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join("/results", phase+"-recovery.json"), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func assertRelayOpenedVisitors(t *testing.T, before, after separatedSnapshot, role string) {
	t.Helper()
	count := func(snapshot separatedSnapshot) uint64 {
		var count uint64
		for _, family := range snapshot.Metrics[role] {
			if family.GetName() != "tnl_operation_duration_seconds" {
				continue
			}
			for _, metric := range family.Metric {
				labels := make(map[string]string)
				for _, label := range metric.Label {
					labels[label.GetName()] = label.GetValue()
				}
				if labels["operation"] == "RelayOpenVisitorStream" && labels["outcome"] == "success" {
					count += metric.GetHistogram().GetSampleCount()
				}
			}
		}
		return count
	}
	if count(after) <= count(before) {
		t.Errorf("%s accepted no visitor streams during measurement", role)
	}
}

// Sample production freshness/connection/stream gauges during traffic rather than
// inferring their peaks from the idle phase endpoints. Raw endpoint scrapes retain
// all counters, including source/capacity rejections and database pool waiting.
func sampleSeparatedGauges(t *testing.T, phase string) func() {
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		client := &http.Client{Timeout: time.Second}
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			for _, role := range []string{"control", "ingress", "relay-a", "relay-b"} {
				if (phase == "relay-restart" || phase == "relay-kill") && role == "relay-a" {
					continue
				}
				response, err := integrationGET(ctx, client, "http://"+role+":9090/metrics")
				if err != nil {
					if ctx.Err() == nil {
						t.Errorf("gauge sample %s: %v", role, err)
					}
					return
				}
				families, err := observability.ParseMetrics(response.Body)
				_ = response.Body.Close()
				if err != nil || response.StatusCode != http.StatusOK {
					if ctx.Err() == nil {
						t.Errorf("gauge sample %s: status=%d error=%v", role, response.StatusCode, err)
					}
					return
				}
				for _, family := range families {
					name := family.GetName()
					if !strings.HasPrefix(name, "tnl_ingress_routing_") && name != "tnl_streams_active" && name != "tnl_publisher_connections" && name != "tnl_database_pool_acquired_connections" {
						continue
					}
					for _, metric := range family.Metric {
						if metric.Gauge != nil {
							t.Logf("separated_gauge phase=%s role=%s metric=%s labels=%v value=%g", phase, role, name, metric.Label, metric.Gauge.GetValue())
						}
					}
				}
			}
		}
	}()
	stop := func() { cancel(); <-done }
	t.Cleanup(stop)
	return stop
}
