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
	runtimeLoadHeldStreams        = flag.Int("tnl-runtime-load-held-streams", 8, "total held visitor streams")
	runtimeLoadHeldWarmup         = flag.Duration("tnl-runtime-load-held-warmup", 0, "optional held-stream warmup per path (0s-2m)")
	runtimeLoadHeldMeasure        = flag.Duration("tnl-runtime-load-held-measure", 0, "optional held-stream measurement per path (0s-5m)")
	runtimeLoadHeapProfile        = flag.Bool("tnl-runtime-load-heap-profile", false, "capture live Go heap profiles after steady held traffic")
	runtimeLoadCapacityOnly       = flag.Bool("tnl-runtime-load-capacity-only", false, "measure direct and tunneled capacity without a fault phase")
	runtimeLoadDirectPath         = flag.Bool("tnl-runtime-load-direct-path", false, "measure fresh requests directly against the local service")
	runtimeLoadBandwidthDirection = flag.String("tnl-runtime-load-bandwidth-direction", "", "optional downstream, upstream, or bidirectional bandwidth measurement")
	runtimeLoadBandwidthMbits     = flag.Int64("tnl-runtime-load-bandwidth-mbits-per-second", 100, "bandwidth target in decimal megabits/second per direction")
	runtimeLoadBandwidthStreams   = flag.Int("tnl-runtime-load-bandwidth-streams", 64, "bandwidth streams per direction")
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
	t.Logf("separated_load routes=%d rps=%d held=%d held_warmup=%s held_measure=%s sources=4 workers=%d queue=%d payload=32768 phase_duration=%s", routes, rate, *runtimeLoadHeldStreams, *runtimeLoadHeldWarmup, *runtimeLoadHeldMeasure, *runtimeLoadWorkers, *runtimeLoadQueue, duration)
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
	if *runtimeLoadDirectPath {
		separatedCapacityPhase(t, database, &sequence, benchworkload.Phase{
			Name: "direct-fresh", Direct: true, URLs: []string{"https://direct." + separatedDomain},
		}, duration)
	}
	if *runtimeLoadBandwidthDirection != "" {
		bandwidth := &benchworkload.BandwidthConfig{
			Direction: *runtimeLoadBandwidthDirection, Streams: *runtimeLoadBandwidthStreams,
			BytesPerSecond: *runtimeLoadBandwidthMbits * 1_000_000 / 8,
		}
		direct := separatedCapacityPhase(t, database, &sequence, benchworkload.Phase{
			Name: "direct-bandwidth", Direct: true, URLs: []string{"https://direct." + separatedDomain}, Bandwidth: bandwidth,
		}, duration)
		tunneled := separatedCapacityPhase(t, database, &sequence, benchworkload.Phase{
			Name: "tunnel-bandwidth", URLs: publishers.URLs, Bandwidth: bandwidth,
		}, duration)
		t.Logf("separated_bandwidth_comparison direction=%s direct_elapsed=%s tunnel_elapsed=%s", bandwidth.Direction, direct.Elapsed, tunneled.Elapsed)
	}
	if *runtimeLoadHeldStreams > 0 {
		heldDuration := duration
		if *runtimeLoadHeldMeasure > 0 {
			heldDuration = *runtimeLoadHeldMeasure
		}
		if *runtimeLoadDirectPath {
			directURLs := []string{"https://direct." + separatedDomain}
			before := separatedCapture(t, database, "direct-held-open-before")
			separatedProbe(t, &sequence, benchworkload.Phase{Name: "direct-held-open", Direct: true, URLs: directURLs, HeldStreams: *runtimeLoadHeldStreams})
			after := separatedCapture(t, database, "direct-held-open-after")
			separatedReportResources(t, "direct-held-open", before, after)
			assertSeparatedNoRejections(t, "direct-held-open", before, after)
			assertSeparatedNoMemoryLimitEvents(t, "direct-held-open", before, after)
			if *runtimeLoadHeldWarmup > 0 {
				separatedCapacityPhase(t, database, &sequence, benchworkload.Phase{Name: "direct-held-warmup", Direct: true, URLs: directURLs}, *runtimeLoadHeldWarmup)
			}
			separatedCapacityPhase(t, database, &sequence, benchworkload.Phase{Name: "direct-held-steady", Direct: true, URLs: directURLs}, heldDuration)
			separatedProbe(t, &sequence, benchworkload.Phase{Name: "direct-held-close", Direct: true, URLs: directURLs, CloseHeld: true})
		}
		before := separatedCapture(t, database, "initial-held-before")
		separatedProbe(t, &sequence, benchworkload.Phase{Name: "initial-held", URLs: publishers.URLs, HeldStreams: *runtimeLoadHeldStreams})
		after := separatedCapture(t, database, "initial-held-after")
		separatedReportResources(t, "initial-held", before, after)
		assertSeparatedNoRejections(t, "initial-held", before, after)
		assertSeparatedNoMemoryLimitEvents(t, "initial-held", before, after)
		if *runtimeLoadHeldWarmup > 0 {
			separatedCapacityPhase(t, database, &sequence, benchworkload.Phase{Name: "tunnel-held-warmup", URLs: publishers.URLs}, *runtimeLoadHeldWarmup)
		}
	}
	phases := []string{"steady", "shutdown"}
	if !*runtimeLoadCapacityOnly {
		phases = []string{"steady", *runtimeLoadScenario, "shutdown"}
	}
	for _, phase := range phases {
		before := separatedCapture(t, database, phase+"-before")
		stopSamples := sampleSeparatedGauges(t, phase)
		stopResources := func() {}
		if phase == "steady" && *runtimeLoadHeldMeasure > 0 {
			stopResources = sampleSeparatedResources(t, phase)
		}
		start := time.Now().Add(time.Second)
		var restart separatedRestart
		var repaired time.Time
		var oldRelayRun string
		window := duration
		if phase == "steady" && *runtimeLoadHeldStreams > 0 && *runtimeLoadHeldMeasure > 0 {
			window = *runtimeLoadHeldMeasure
		}
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
		if phase == "relay-kill" {
			if err := database.QueryRowContext(integrationOperationContext(t), `SELECT relay_run_id FROM control.relay_leases WHERE relay_id = 'relay-a-1'`).Scan(&oldRelayRun); err != nil {
				t.Fatal(err)
			}
			separatedWrite(t, "fault.request", phase)
			separatedWait(t, "fault.applied", 15*time.Second, &restart)
			start = time.Now().Add(time.Second)
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
			var restored time.Time
			separatedWait(t, "fault.restored", 45*time.Second, &restored)
			restart.Restored = restored
			separatedWait(t, "relay-a.restarted", 10*time.Second, nil)
			waitForIntegrationCondition(t, 25*time.Second, func(ctx context.Context) (bool, error) {
				var current string
				err := database.QueryRowContext(ctx, `SELECT relay_run_id FROM control.relay_leases WHERE relay_id='relay-a-1' AND lease_expires_at>now() AND NOT draining`).Scan(&current)
				return current != "" && current != oldRelayRun, err
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
		results := separatedCollectVisitors(t, phase, 15*time.Second)
		stopSamples()
		stopResources()
		after := separatedCapture(t, database, phase+"-after")
		separatedReportResources(t, phase, before, after)
		if !runtimeControlledFault(phase) {
			separatedReportVisitors(t, phase, results, restart, repaired)
		}
		if phase == "steady" && *runtimeLoadHeldStreams > 0 {
			separatedReportHeld(t, phase, results, *runtimeLoadHeldStreams, false, true, false)
			assertSeparatedNoRejections(t, phase, before, after)
			assertSeparatedNoMemoryLimitEvents(t, phase, before, after)
		}
		if phase == "steady" && *runtimeLoadHeapProfile {
			captureSeparatedHeapProfiles(t, database, after)
		}
		if phase == "steady" && runtimeBlackhole(*runtimeLoadScenario) {
			assertRelayOpenedVisitors(t, before, after, "relay-a")
		}
		// Cover every live route, not only routes sampled late in a traffic window.
		separatedProbe(t, &sequence, benchworkload.Phase{Name: phase + "-correctness", URLs: urls})
		if phase == "steady" && *runtimeLoadCapacityOnly && *runtimeLoadHeldStreams > 0 {
			separatedProbe(t, &sequence, benchworkload.Phase{Name: "tunnel-held-close", URLs: publishers.URLs, CloseHeld: true})
		}
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
	if rate < 4 || rate > 2000 {
		t.Fatal("separated runtime load requests per second must be between 4 and 2000")
	}
	if duration < 10*time.Second || duration > 2*time.Minute {
		t.Fatal("separated runtime load phase duration must be between 10s and 2m")
	}
	if *runtimeLoadWorkers < 4 || *runtimeLoadWorkers > 4096 || *runtimeLoadQueue < 0 || *runtimeLoadQueue > 4096 {
		t.Fatal("invalid visitor concurrency or queue")
	}
	if *runtimeLoadHeldStreams < 0 || *runtimeLoadHeldStreams > 20000 {
		t.Fatal("held streams must be between 0 and 20000")
	}
	if *runtimeLoadHeldWarmup < 0 || *runtimeLoadHeldWarmup > 2*time.Minute || *runtimeLoadHeldMeasure < 0 || *runtimeLoadHeldMeasure > 5*time.Minute ||
		(*runtimeLoadHeldStreams == 0 && (*runtimeLoadHeldWarmup != 0 || *runtimeLoadHeldMeasure != 0)) {
		t.Fatal("invalid held-stream warmup or measurement duration")
	}
	if *runtimeLoadHeapProfile && *runtimeLoadHeldStreams == 0 {
		t.Fatal("heap profiling requires held streams")
	}
	if *runtimeLoadBandwidthDirection != "" {
		if !slices.Contains([]string{benchworkload.BandwidthDownstream, benchworkload.BandwidthUpstream, benchworkload.BandwidthBidirectional}, *runtimeLoadBandwidthDirection) {
			t.Fatal("invalid bandwidth direction")
		}
		if *runtimeLoadBandwidthStreams < 4 || *runtimeLoadBandwidthStreams > 4096 || *runtimeLoadBandwidthMbits < 1 || *runtimeLoadBandwidthMbits > 10_000 {
			t.Fatal("invalid bandwidth rate or stream count")
		}
	}
	if !slices.Contains([]string{"relay-restart", "relay-kill", "forwarding-blackhole", "publisher-blackhole", "udp-fallback", "latency", "packet-loss"}, *runtimeLoadScenario) {
		t.Fatal("invalid runtime scenario")
	}
	if *runtimeLoadCapacityOnly && *runtimeLoadScenario != "relay-restart" {
		t.Fatal("capacity-only workload requires the default scenario")
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

func separatedCapacityPhase(t *testing.T, database *sql.DB, sequence *int, phase benchworkload.Phase, duration time.Duration) benchworkload.BandwidthResult {
	t.Helper()
	before := separatedCapture(t, database, phase.Name+"-before")
	stopSamples := sampleSeparatedGauges(t, phase.Name)
	stopResources := func() {}
	if *runtimeLoadHeldMeasure > 0 && (phase.Name == "direct-held-steady" || phase.Name == "tunnel-held-warmup") {
		stopResources = sampleSeparatedResources(t, phase.Name)
	}
	phase.Start, phase.Duration = time.Now().Add(time.Second), duration
	separatedWrite(t, fmt.Sprintf("phase-%d", *sequence), phase)
	*sequence = *sequence + 1
	waitUntilIntegrationTime(t, phase.Start.Add(duration))
	results := separatedCollectVisitors(t, phase.Name, 30*time.Second)
	stopSamples()
	stopResources()
	after := separatedCapture(t, database, phase.Name+"-after")
	separatedReportResources(t, phase.Name, before, after)
	if phase.Bandwidth == nil {
		separatedReportVisitors(t, phase.Name, results, separatedRestart{}, time.Time{})
		if phase.Name == "direct-held-steady" || phase.Name == "direct-held-warmup" || phase.Name == "tunnel-held-warmup" {
			separatedReportHeld(t, phase.Name, results, *runtimeLoadHeldStreams, false, true, false)
			assertSeparatedNoRejections(t, phase.Name, before, after)
			assertSeparatedNoMemoryLimitEvents(t, phase.Name, before, after)
		}
		return benchworkload.BandwidthResult{}
	}
	aggregate := benchworkload.BandwidthResult{
		Direction: phase.Bandwidth.Direction, StreamsPerDirection: phase.Bandwidth.Streams,
		TargetBytesPerSecond: phase.Bandwidth.BytesPerSecond, TargetDuration: duration, StartedAt: phase.Start,
	}
	for _, result := range results {
		if result.Bandwidth == nil {
			t.Error("bandwidth visitor returned no result")
			continue
		}
		bandwidth := result.Bandwidth
		aggregate.Elapsed = max(aggregate.Elapsed, bandwidth.Elapsed)
		aggregate.ExpectedUploadBytes += bandwidth.ExpectedUploadBytes
		aggregate.UploadBytes += bandwidth.UploadBytes
		aggregate.ExpectedDownloadBytes += bandwidth.ExpectedDownloadBytes
		aggregate.DownloadBytes += bandwidth.DownloadBytes
		aggregate.Failures += bandwidth.Failures
		for _, sample := range bandwidth.FailureSamples {
			if len(aggregate.FailureSamples) < 8 {
				aggregate.FailureSamples = append(aggregate.FailureSamples, sample)
			}
		}
	}
	if err := aggregate.Err(); err != nil {
		t.Error(err)
	}
	seconds := aggregate.Elapsed.Seconds()
	aggregate.UploadBytesPerSecond = float64(aggregate.UploadBytes) / seconds
	aggregate.DownloadBytesPerSecond = float64(aggregate.DownloadBytes) / seconds
	uploadMbits, downloadMbits := aggregate.UploadBytesPerSecond*8/1_000_000, aggregate.DownloadBytesPerSecond*8/1_000_000
	t.Logf("separated_bandwidth phase=%s direction=%s streams_per_direction=%d target_mbits_per_second=%d upload_mbits_per_second=%.3f download_mbits_per_second=%.3f failures=%d elapsed=%s",
		phase.Name, aggregate.Direction, aggregate.StreamsPerDirection, *runtimeLoadBandwidthMbits, uploadMbits, downloadMbits, aggregate.Failures, aggregate.Elapsed)
	separatedResult(t, phase.Name+"-summary", aggregate)
	return aggregate
}

func separatedCollectVisitors(t *testing.T, phase string, timeout time.Duration) []separatedVisitorResult {
	t.Helper()
	var results []separatedVisitorResult
	for i := 1; i <= 4; i++ {
		var result separatedVisitorResult
		separatedWait(t, fmt.Sprintf("%s.visitor-%d", phase, i), timeout, &result)
		results = append(results, result)
	}
	separatedResult(t, phase+"-visitors", results)
	return results
}

type separatedHeldSummary struct {
	Requested       int           `json:"requested"`
	Opened          int           `json:"opened"`
	Surviving       int           `json:"surviving"`
	Progressing     int           `json:"progressing"`
	Closed          int           `json:"closed"`
	OpeningDuration time.Duration `json:"opening_duration"`
}

func separatedReportHeld(t *testing.T, phase string, results []separatedVisitorResult, expected int, opening, measuring, closing bool) {
	t.Helper()
	var summary separatedHeldSummary
	for _, result := range results {
		summary.Requested += result.HeldRequested
		summary.Opened += result.HeldOpened
		summary.Surviving += result.HeldSurviving
		summary.Progressing += result.HeldProgressing
		summary.Closed += result.HeldClosed
		summary.OpeningDuration = max(summary.OpeningDuration, result.HeldOpeningDuration)
	}
	t.Logf("separated_held phase=%s requested=%d opened=%d surviving=%d progressing=%d closed=%d opening_duration=%s", phase,
		summary.Requested, summary.Opened, summary.Surviving, summary.Progressing, summary.Closed, summary.OpeningDuration)
	separatedResult(t, phase+"-held-summary", summary)
	if opening && (summary.Requested != expected || summary.Opened != expected || summary.Surviving != expected) {
		t.Errorf("%s: requested=%d opened=%d surviving=%d, want %d", phase, summary.Requested, summary.Opened, summary.Surviving, expected)
	}
	if measuring && (summary.Surviving != expected || summary.Progressing != expected) {
		t.Errorf("%s: surviving=%d progressing=%d, want %d", phase, summary.Surviving, summary.Progressing, expected)
	}
	if closing && summary.Closed != expected {
		t.Errorf("%s: closed=%d, want %d", phase, summary.Closed, expected)
	}
}

func assertSeparatedNoRejections(t *testing.T, phase string, before, after separatedSnapshot) {
	t.Helper()
	for _, role := range []string{"ingress", "relay-a", "relay-b"} {
		for _, name := range []string{"tnl_capacity_rejections_total", "tnl_source_limiter_rejections_total"} {
			count := func(snapshot separatedSnapshot) float64 {
				var total float64
				for _, family := range snapshot.Metrics[role] {
					if family.GetName() == name {
						for _, metric := range family.Metric {
							total += metric.GetCounter().GetValue()
						}
					}
				}
				return total
			}
			if delta := count(after) - count(before); delta != 0 {
				t.Errorf("%s: %s %s changed by %g", phase, role, name, delta)
			}
		}
	}
}

func assertSeparatedNoMemoryLimitEvents(t *testing.T, phase string, before, after separatedSnapshot) {
	t.Helper()
	for _, component := range []string{"ingress", "relay-a", "relay-b", "app", "publishers", "visitor-1", "visitor-2", "visitor-3", "visitor-4"} {
		a, b := before.Resources[component], after.Resources[component]
		if b.MemoryMaxEvents > a.MemoryMaxEvents || b.OOMKills > a.OOMKills {
			t.Errorf("%s: %s memory limit events=%d OOM kills=%d", phase, component, b.MemoryMaxEvents-a.MemoryMaxEvents, b.OOMKills-a.OOMKills)
		}
	}
}

func separatedResult(t *testing.T, name string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("/results", name+".json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
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
	postgres.Postgres = &separatedPostgresResources{}
	if err := database.QueryRowContext(integrationOperationContext(t), `SELECT
		(SELECT coalesce(sum(allocated_size), 0)::bigint FROM pg_shmem_allocations),
		pg_size_bytes(current_setting('shared_buffers')),
		numbackends, blks_read, blks_hit, temp_bytes
		FROM pg_stat_database WHERE datname = current_database()`).Scan(
		&postgres.Postgres.SharedMemoryBytes, &postgres.Postgres.SharedBuffersBytes,
		&postgres.Postgres.Backends, &postgres.Postgres.BlocksRead,
		&postgres.Postgres.BlocksHit, &postgres.Postgres.TempBytes,
	); err != nil {
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
			t.Logf("separated_resource phase=%s component=%s interval_reset=true before_run=%s after_run=%s memory=%d peak=%d fds=%d memory_anon=%d memory_file=%d memory_kernel=%d memory_kernel_stack=%d memory_pagetables=%d memory_sock=%d memory_slab=%d memory_shmem=%d memory_file_dirty=%d memory_file_writeback=%d memory_high_events=%d memory_max_events=%d oom_events=%d oom_kills=%d",
				phase, component, a.ProcessRunID, b.ProcessRunID, b.Memory, b.Peak, b.OpenFileDescriptors,
				b.MemoryAnon, b.MemoryFile, b.MemoryKernel, b.MemoryKernelStack, b.MemoryPageTables, b.MemorySock, b.MemorySlab, b.MemoryShmem,
				b.MemoryFileDirty, b.MemoryFileWriteback, b.MemoryHighEvents, b.MemoryMaxEvents, b.OOMEvents, b.OOMKills)
			if b.OOMKills != 0 {
				t.Errorf("%s OOM after restart", component)
			}
			continue
		}
		seconds := b.At.Sub(a.At).Seconds()
		t.Logf("separated_resource phase=%s component=%s interval=%.3fs quota=%q memory_limit=%q cpu_seconds=%.6f cpu_cores=%.4f throttled_seconds=%.6f throttled_periods=%d/%d memory=%d peak=%d fds=%d memory_anon=%d memory_file=%d memory_kernel=%d memory_kernel_stack=%d memory_pagetables=%d memory_sock=%d memory_slab=%d memory_shmem=%d memory_file_dirty=%d memory_file_writeback=%d memory_high_events=%d memory_max_events=%d oom_events=%d oom_kills=%d rx_bytes=%d tx_bytes=%d gomaxprocs=%d network_namespace=%s",
			phase, component, seconds, b.CPUQuota, b.MemoryLimit, float64(b.CPUUsec-a.CPUUsec)/1e6, float64(b.CPUUsec-a.CPUUsec)/1e6/seconds,
			float64(b.ThrottledUsec-a.ThrottledUsec)/1e6, b.ThrottledPeriods-a.ThrottledPeriods, b.Periods-a.Periods, b.Memory, b.Peak, b.OpenFileDescriptors,
			b.MemoryAnon, b.MemoryFile, b.MemoryKernel, b.MemoryKernelStack, b.MemoryPageTables, b.MemorySock, b.MemorySlab, b.MemoryShmem,
			b.MemoryFileDirty, b.MemoryFileWriteback, b.MemoryHighEvents-a.MemoryHighEvents, b.MemoryMaxEvents-a.MemoryMaxEvents,
			b.OOMEvents-a.OOMEvents, b.OOMKills-a.OOMKills,
			b.ReceiveBytes-a.ReceiveBytes, b.SendBytes-a.SendBytes, b.GOMAXPROCS, b.NetworkNamespace)
		if b.OOMKills > a.OOMKills {
			t.Errorf("%s OOM in %s", component, phase)
		}
		if component == "postgres" && a.Postgres != nil && b.Postgres != nil {
			t.Logf("separated_postgres phase=%s shared_memory=%d shared_buffers=%d backends=%d blocks_read=%d blocks_hit=%d temp_bytes=%d",
				phase, b.Postgres.SharedMemoryBytes, b.Postgres.SharedBuffersBytes, b.Postgres.Backends,
				b.Postgres.BlocksRead-a.Postgres.BlocksRead, b.Postgres.BlocksHit-a.Postgres.BlocksHit, b.Postgres.TempBytes-a.Postgres.TempBytes)
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
			if phase == "relay-kill" {
				if err := validateRelayKillVisitor(row, restart.Exited); err != nil {
					t.Error(err)
				}
			}
			if row.Error != "" {
				failures++
				if failures <= 3 {
					t.Logf("separated_request_failure phase=%s started=%s error=%s", phase, row.Started, row.Error)
				}
				if phase != "relay-kill" && (runtimeControlledFault(phase) || phase != *runtimeLoadScenario || !row.Started.Before(repaired)) {
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
	separatedResult(t, phase+"-summary", merged)
	if missed != 0 || total == 0 {
		t.Errorf("phase %s: missed=%d requests=%d", phase, missed, total)
	}
	separatedResult(t, phase+"-cohorts", cohorts)
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
		separatedResult(t, phase+"-recovery", struct {
			Scenario                                          string
			Fault                                             separatedRestart
			FirstSuccessfulBodyAfterApplied, VerifiedRecovery time.Time
			HeldSurviving                                     int
		}{phase, restart, firstExit, repaired, surviving})
	}
}

func validateRelayKillVisitor(row benchworkload.RequestResult, relayExited time.Time) error {
	if relayExited.IsZero() {
		return fmt.Errorf("relay-kill visitor has no relay exit boundary")
	}
	if row.Started.Before(relayExited) {
		return fmt.Errorf("relay-kill visitor started before relay exit")
	}
	if row.Error != "" {
		return fmt.Errorf("relay-kill visitor failed after relay exit: %s", row.Error)
	}
	return nil
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
