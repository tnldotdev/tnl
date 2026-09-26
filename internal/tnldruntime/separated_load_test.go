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
	"github.com/tnldotdev/tnl/internal/publisher"
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
	runtimeLoadCPUProfile         = flag.Bool("tnl-runtime-load-cpu-profile", false, "capture on-demand relay CPU profiles during steady traffic")
	runtimeLoadCapacityOnly       = flag.Bool("tnl-runtime-load-capacity-only", false, "measure direct and tunneled capacity without a fault phase")
	runtimeLoadCombined           = flag.Bool("tnl-runtime-load-combined", false, "measure fresh connections, held streams, and bidirectional bandwidth at the same time")
	runtimeLoadHATopology         = flag.Bool("tnl-runtime-load-ha-topology", true, "run two control and two ingress processes in the local separated topology")
	runtimeLoadDirectPath         = flag.Bool("tnl-runtime-load-direct-path", false, "measure fresh requests directly against the local service")
	runtimeLoadBandwidthDirection = flag.String("tnl-runtime-load-bandwidth-direction", "", "optional downstream, upstream, or bidirectional bandwidth measurement")
	runtimeLoadBandwidthMbits     = flag.Int64("tnl-runtime-load-bandwidth-mbits-per-second", 100, "bandwidth target in decimal megabits/second per direction")
	runtimeLoadBandwidthStreams   = flag.Int("tnl-runtime-load-bandwidth-streams", 64, "bandwidth streams per direction")
	runtimeLoadBandwidthMeasure   = flag.Duration("tnl-runtime-load-bandwidth-measure", 0, "optional bandwidth measurement per path (0s-5m)")
	runtimeLoadScenario           = flag.String("tnl-runtime-load-scenario", "relay-restart", "relay-restart, relay-kill, control-restart, forwarding-blackhole, publisher-blackhole, udp-fallback, latency, or packet-loss")
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
	for _, name := range append(append(separatedServerRoles(), separatedAppComponents()...), "pebble") {
		separatedWait(t, name+".ready", 30*time.Second, nil)
	}
	verifySeparatedAdmission(t)
	var initialFault separatedRestart
	if runtimeEarlyFault(*runtimeLoadScenario) {
		separatedWrite(t, "fault.request", *runtimeLoadScenario)
		separatedWait(t, "fault.applied", 15*time.Second, &initialFault)
		t.Logf("network_impairment scenario=%s path=%s added_rtt=%s loss_percent=%g active_before_publishing=true", *runtimeLoadScenario, *runtimeLoadNetworkPath, *runtimeLoadRTT, *runtimeLoadLoss)
	}
	for _, component := range separatedActiveComponents() {
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
	publishers := separatedPublishers{URLs: make([]string, routes), Ready: make([]publisher.Event, routes)}
	// Each publisher retains its own readiness deadline, starting at launch.
	parallel := min(routes, *runtimeLoadStartParallel)
	waves := (routes + parallel - 1) / parallel
	for shard := range separatedPublisherComponents() {
		var result separatedPublishers
		separatedWait(t, separatedPublisherShardKey(shard, "ready"), time.Duration(waves)*(*runtimeLoadReadyTimeout)+10*time.Second, &result)
		if len(result.URLs) != routes || len(result.Ready) != routes {
			t.Fatalf("publisher shard %d has incomplete route slots", shard+1)
		}
		for index, url := range result.URLs {
			if url == "" {
				continue
			}
			if publishers.URLs[index] != "" || result.Ready[index].Type != publisher.EventReady || result.Ready[index].PublicURL != url {
				t.Fatalf("publisher shard %d has duplicate or invalid route index %d", shard+1, index)
			}
			publishers.URLs[index], publishers.Ready[index] = url, result.Ready[index]
		}
		publishers.Activation = append(publishers.Activation, result.Activation...)
		publishers.ActivationDuration = max(publishers.ActivationDuration, result.ActivationDuration)
		publishers.Fallbacks += result.Fallbacks
	}
	stopTrace()
	for index, url := range publishers.URLs {
		if url == "" {
			t.Fatalf("publisher route %d was not activated", index)
		}
	}
	separatedWrite(t, "publishers.ready", publishers)
	if *runtimeLoadScenario == "udp-fallback" && publishers.Fallbacks != int64(routes) {
		t.Fatalf("fallback events=%d want=%d", publishers.Fallbacks, routes)
	}
	if *runtimeLoadScenario == "udp-fallback" {
		separatedWait(t, "udp.cleaned", 15*time.Second, nil)
	}
	for _, ready := range publishers.Ready {
		waitForReadyPublisherConnections(t, database, ready.RouteID, ready.RouteVersion, 2)
	}
	waitForIngressRoutingCurrent(t, database, len(separatedIngresses()))
	var orders, installed, distinctRoutes int
	var workerAttempts int64
	if err := database.QueryRowContext(integrationOperationContext(t), `SELECT count(*), count(*) FILTER (WHERE state = 'installed'), count(DISTINCT route_id), coalesce(sum(attempts), 0) FROM control.acme_orders`).Scan(&orders, &installed, &distinctRoutes, &workerAttempts); err != nil {
		t.Fatal(err)
	}
	caOrders := separatedCAOrders(t)
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
	if *runtimeLoadBandwidthDirection != "" && !*runtimeLoadCombined {
		bandwidthDuration := duration
		if *runtimeLoadBandwidthMeasure > 0 {
			bandwidthDuration = *runtimeLoadBandwidthMeasure
		}
		bandwidth := &benchworkload.BandwidthConfig{
			Direction: *runtimeLoadBandwidthDirection, Streams: *runtimeLoadBandwidthStreams,
			BytesPerSecond: *runtimeLoadBandwidthMbits * 1_000_000 / 8,
		}
		direct := separatedCapacityPhase(t, database, &sequence, benchworkload.Phase{
			Name: "direct-bandwidth", Direct: true, URLs: []string{"https://direct." + separatedDomain}, Bandwidth: bandwidth,
		}, bandwidthDuration)
		tunneled := separatedCapacityPhase(t, database, &sequence, benchworkload.Phase{
			Name: "tunnel-bandwidth", URLs: publishers.URLs, Bandwidth: bandwidth,
		}, bandwidthDuration)
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
			directPhase := benchworkload.Phase{Name: "direct-held-steady", Direct: true, URLs: directURLs}
			if *runtimeLoadCombined {
				directPhase.Combined = true
				directPhase.Bandwidth = separatedBandwidthConfig()
			}
			separatedCapacityPhase(t, database, &sequence, directPhase, heldDuration)
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
		var controlRestartAssignments string
		if phase == "control-restart" {
			controlRestartAssignments = separatedConnectionAssignments(t, database)
		}
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
		if phase == "control-restart" {
			window = max(window, 85*time.Second)
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
		visitorPhase := benchworkload.Phase{Name: phase, Start: start, Duration: window, URLs: urls, CloseHeld: phase == *runtimeLoadScenario && !runtimeEarlyFault(phase)}
		if phase == "steady" && *runtimeLoadCombined {
			visitorPhase.Combined = true
			visitorPhase.Bandwidth = separatedBandwidthConfig()
		}
		separatedWrite(t, fmt.Sprintf("phase-%d", sequence), visitorPhase)
		sequence++
		waitUntilIntegrationTime(t, start.Add(time.Second))
		if phase == "steady" && *runtimeLoadCPUProfile {
			captureSeparatedCPUProfiles(t)
		}
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
			// A killed relay waits out its 30-second lease. The next 15-second
			// publisher heartbeat can then assign replacement connections.
			repaired = separatedWaitForRecovery(t, database, publishers, 45*time.Second)
			var currentRelayRun string
			if err := database.QueryRowContext(integrationOperationContext(t), `SELECT relay_run_id FROM control.relay_leases WHERE relay_id='relay-a-1' AND lease_expires_at>now() AND NOT draining`).Scan(&currentRelayRun); err != nil {
				t.Fatal(err)
			}
			if currentRelayRun == oldRelayRun {
				t.Fatalf("killed relay retained process run ID %s after recovery", oldRelayRun)
			}
		}
		switch phase {
		case "relay-restart":
			separatedWrite(t, "relay-a.restart", time.Now())
			separatedWait(t, "relay-a.stopped", 10*time.Second, &restart)
			separatedWait(t, "relay-a.restarted", 10*time.Second, nil)
			repaired = separatedWaitForRecovery(t, database, publishers, 25*time.Second)
		case "control-restart":
			separatedWrite(t, "control-a.restart", time.Now())
			separatedWait(t, "control-a.stopped", 15*time.Second, &restart)
			separatedWait(t, "control-a.restarted", 70*time.Second, &restart.Restored)
			repaired = separatedWaitForRecovery(t, database, publishers, 25*time.Second)
		case "shutdown":
			separatedWrite(t, "close-half", time.Now())
			var elapsed time.Duration
			for shard := range separatedPublisherComponents() {
				var duration time.Duration
				separatedWait(t, separatedPublisherShardKey(shard, "close-half.done"), time.Duration((routes/2+3)/4)*10*time.Second, &duration)
				elapsed = max(elapsed, duration)
			}
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
		if phase == "steady" && *runtimeLoadHATopology {
			assertSeparatedIngressTraffic(t, before, after)
		}
		if visitorPhase.Combined {
			separatedReportBandwidth(t, phase, start, window, visitorPhase.Bandwidth, results, true)
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
			repaired = separatedWaitForRecovery(t, database, publishers, 25*time.Second)
			separatedProbe(t, &sequence, benchworkload.Phase{Name: phase + "-restored", URLs: publishers.URLs, CloseHeld: true})
			separatedReportVisitors(t, phase, results, restart, repaired)
		}
		if phase == "control-restart" {
			if assignments := separatedConnectionAssignments(t, database); assignments != controlRestartAssignments {
				t.Errorf("control restart replaced ready publisher connections: before=%s after=%s", controlRestartAssignments, assignments)
			}
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
	for shard := range separatedPublisherComponents() {
		var duration time.Duration
		separatedWait(t, separatedPublisherShardKey(shard, "close-all.done"), time.Duration(((routes+1)/2+3)/4)*10*time.Second, &duration)
		elapsed = max(elapsed, duration)
	}
	t.Logf("separated_final_shutdown publishers=%d elapsed=%s", (routes+1)/2, elapsed)
	waitForIntegrationCondition(t, 10*time.Second, func(ctx context.Context) (bool, error) {
		var active int
		err := database.QueryRowContext(ctx, `SELECT
			(SELECT count(*) FROM control.route_sessions WHERE closed_at IS NULL OR assignments_open) +
			(SELECT count(*) FROM control.route_session_connections WHERE state <> 'closed') +
			(SELECT coalesce(sum(assignment_count), 0) FROM control.relay_service_assignment_totals)`).Scan(&active)
		return active == 0, err
	})
	routingTimeout := 10 * time.Second
	if *runtimeLoadCapacityOnly {
		routingTimeout = 30 * time.Second
	}
	waitForIngressRoutingCurrentWithin(t, database, len(separatedIngresses()), routingTimeout)
	separatedCapture(t, database, "final")
	if got := separatedCAOrders(t); got != int64(routes) {
		t.Errorf("certificate issuance changed during workload: got %d want %d", got, routes)
	}
	// Stop ingress while control and PostgreSQL remain available. Its production
	// reporter flushes final checkpoints and marks this process run complete.
	stoppingIngress := time.Now()
	ingressStopTimeout := 10 * time.Second
	if *runtimeLoadCapacityOnly {
		ingressStopTimeout = 35 * time.Second
	}
	for _, ingress := range separatedIngresses() {
		separatedWrite(t, ingress+".stop", time.Now())
		separatedWait(t, ingress+".stopped", ingressStopTimeout, nil)
	}
	ingressStopElapsed := time.Since(stoppingIngress)
	t.Logf("separated_ingress_shutdown elapsed=%s", ingressStopElapsed)
	separatedResult(t, "ingress-shutdown", map[string]any{"elapsed": ingressStopElapsed.String()})
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
	separatedConfig(t, "ingress-a")
	routes, rate, duration := *runtimeLoadRoutes, *runtimeLoadRPS, *runtimeLoadDuration
	if routes < 4 || routes > 10000 {
		t.Fatal("separated runtime load routes must be between 4 and 10000")
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
	maxDuration := 2 * time.Minute
	if *runtimeLoadCapacityOnly {
		maxDuration = 5 * time.Minute
	}
	if duration < 10*time.Second || duration > maxDuration {
		t.Fatalf("separated runtime load phase duration must be between 10s and %s", maxDuration)
	}
	if *runtimeLoadWorkers < 4 || *runtimeLoadWorkers > 4096 || *runtimeLoadQueue < 0 || *runtimeLoadQueue > 4096 {
		t.Fatal("invalid visitor concurrency or queue")
	}
	if *runtimeLoadHeldStreams < 0 || *runtimeLoadHeldStreams > 20000 {
		t.Fatal("held streams must be between 0 and 20000")
	}
	if runtimeLoadAdmission.PublisherRequestLimit < 1 {
		t.Fatal("publisher request limit must be positive")
	}
	if *runtimeLoadHeldWarmup < 0 || *runtimeLoadHeldWarmup > 2*time.Minute || *runtimeLoadHeldMeasure < 0 || *runtimeLoadHeldMeasure > 5*time.Minute ||
		(*runtimeLoadHeldStreams == 0 && (*runtimeLoadHeldWarmup != 0 || *runtimeLoadHeldMeasure != 0)) {
		t.Fatal("invalid held-stream warmup or measurement duration")
	}
	if *runtimeLoadHeapProfile && *runtimeLoadHeldStreams == 0 {
		t.Fatal("heap profiling requires held streams")
	}
	if *runtimeLoadCPUProfile && (!*runtimeLoadCapacityOnly || *runtimeLoadHeldMeasure < 40*time.Second) {
		t.Fatal("CPU profiling requires a capacity-only steady window of at least 40 seconds")
	}
	if *runtimeLoadBandwidthDirection != "" {
		if !slices.Contains([]string{benchworkload.BandwidthDownstream, benchworkload.BandwidthUpstream, benchworkload.BandwidthBidirectional}, *runtimeLoadBandwidthDirection) {
			t.Fatal("invalid bandwidth direction")
		}
		if *runtimeLoadBandwidthStreams < 4 || *runtimeLoadBandwidthStreams > 4096 || *runtimeLoadBandwidthMbits < 1 || *runtimeLoadBandwidthMbits > 10_000 {
			t.Fatal("invalid bandwidth rate or stream count")
		}
	}
	if *runtimeLoadBandwidthMeasure < 0 || *runtimeLoadBandwidthMeasure > 5*time.Minute || (*runtimeLoadBandwidthMeasure > 0 && *runtimeLoadBandwidthDirection == "") {
		t.Fatal("invalid bandwidth measurement duration")
	}
	if *runtimeLoadCombined && (!*runtimeLoadCapacityOnly || !*runtimeLoadDirectPath || *runtimeLoadHeldStreams == 0 || *runtimeLoadHeldWarmup == 0 || *runtimeLoadHeldMeasure == 0 || *runtimeLoadBandwidthDirection != benchworkload.BandwidthBidirectional ||
		(*runtimeLoadBandwidthMeasure != 0 && *runtimeLoadBandwidthMeasure != *runtimeLoadHeldMeasure)) {
		t.Fatal("combined workload requires capacity-only, direct path, held warmup/measurement, and matched bidirectional bandwidth")
	}
	if !slices.Contains([]string{"relay-restart", "relay-kill", "control-restart", "forwarding-blackhole", "publisher-blackhole", "udp-fallback", "latency", "packet-loss"}, *runtimeLoadScenario) {
		t.Fatal("invalid runtime scenario")
	}
	if *runtimeLoadScenario == "control-restart" && !*runtimeLoadHATopology {
		t.Fatal("control restart requires the two-control topology")
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
	if phase.Bandwidth == nil || phase.Combined {
		separatedReportVisitors(t, phase.Name, results, separatedRestart{}, time.Time{})
		if phase.Name == "direct-held-steady" || phase.Name == "direct-held-warmup" || phase.Name == "tunnel-held-warmup" {
			separatedReportHeld(t, phase.Name, results, *runtimeLoadHeldStreams, false, true, false)
			assertSeparatedNoRejections(t, phase.Name, before, after)
			assertSeparatedNoMemoryLimitEvents(t, phase.Name, before, after)
		}
		if phase.Bandwidth == nil {
			return benchworkload.BandwidthResult{}
		}
	}
	return separatedReportBandwidth(t, phase.Name, phase.Start, duration, phase.Bandwidth, results, phase.Combined)
}

func separatedBandwidthConfig() *benchworkload.BandwidthConfig {
	return &benchworkload.BandwidthConfig{Direction: *runtimeLoadBandwidthDirection,
		Streams: *runtimeLoadBandwidthStreams, BytesPerSecond: *runtimeLoadBandwidthMbits * 1_000_000 / 8}
}

func separatedReportBandwidth(t *testing.T, name string, start time.Time, duration time.Duration, config *benchworkload.BandwidthConfig, results []separatedVisitorResult, combined bool) benchworkload.BandwidthResult {
	t.Helper()
	aggregate := benchworkload.BandwidthResult{
		Direction: config.Direction, StreamsPerDirection: config.Streams,
		TargetBytesPerSecond: config.BytesPerSecond, TargetDuration: duration, StartedAt: start,
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
		name, aggregate.Direction, aggregate.StreamsPerDirection, *runtimeLoadBandwidthMbits, uploadMbits, downloadMbits, aggregate.Failures, aggregate.Elapsed)
	summaryName := name + "-summary"
	if combined {
		summaryName = name + "-bandwidth-summary"
	}
	separatedResult(t, summaryName, aggregate)
	return aggregate
}

func separatedCollectVisitors(t *testing.T, phase string, timeout time.Duration) []separatedVisitorResult {
	t.Helper()
	var results []separatedVisitorResult
	for i := 1; i <= 4; i++ {
		var result separatedVisitorResult
		separatedWait(t, fmt.Sprintf("%s.visitor-%d", phase, i), timeout, &result)
		if result.RequestsFile != "" {
			path := filepath.Join("/results", result.RequestsFile)
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			decoder := json.NewDecoder(file)
			for {
				var row benchworkload.RequestResult
				if err := decoder.Decode(&row); err != nil {
					if err == io.EOF {
						break
					}
					t.Fatal(err)
				}
				result.Requests = append(result.Requests, row)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if len(result.Requests) != result.Completed+result.QueueExpired {
				t.Fatalf("%s request artifact: got %d rows, want %d", path, len(result.Requests), result.Completed+result.QueueExpired)
			}
		}
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
	for _, role := range append(separatedIngresses(), "relay-a", "relay-b") {
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

func assertSeparatedIngressTraffic(t *testing.T, before, after separatedSnapshot) {
	t.Helper()
	for _, role := range separatedIngresses() {
		count := func(snapshot separatedSnapshot) uint64 {
			var total uint64
			for _, family := range snapshot.Metrics[role] {
				if family.GetName() != "tnl_operation_duration_seconds" {
					continue
				}
				for _, metric := range family.Metric {
					labels := make(map[string]string)
					for _, label := range metric.Label {
						labels[label.GetName()] = label.GetValue()
					}
					if labels["operation"] == "IngressBackendAttempt" && labels["outcome"] == "success" {
						total += metric.GetHistogram().GetSampleCount()
					}
				}
			}
			return total
		}
		if delta := count(after) - count(before); delta == 0 {
			t.Errorf("%s accepted no visitor connections during steady traffic", role)
		} else {
			t.Logf("separated_ingress_traffic role=%s backend_attempts=%d", role, delta)
		}
	}
}

func assertSeparatedNoMemoryLimitEvents(t *testing.T, phase string, before, after separatedSnapshot) {
	t.Helper()
	components := append(append(separatedIngresses(), "relay-a", "relay-b"), separatedAppComponents()...)
	components = append(components, separatedPublisherComponents()...)
	components = append(components, "visitor-1", "visitor-2", "visitor-3", "visitor-4")
	for _, component := range components {
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
	for _, component := range separatedActiveComponents() {
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
	for _, role := range separatedServerRoles() {
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
	for _, component := range append(separatedActiveComponents(), "postgres", "coordinator") {
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
	for _, role := range separatedServerRoles() {
		if role == "relay-a" && (phase == "relay-restart" || phase == "relay-kill") || role == "control-a" && phase == "control-restart" {
			continue
		} // New runtime registry.
		summaries, err := separatedDurationSummaries(before, after, role)
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

// The observer's process run ID is stable across clock adjustments. On Docker
// Desktop, process_start_time_seconds can move by a second for every process
// without any process restarting; retain the run-ID check and difference only
// the histograms when the same process produced both snapshots.
func separatedDurationSummaries(before, after separatedSnapshot, role string) ([]observability.DurationSummary, error) {
	start, end := before.Resources[role].ProcessRunID, after.Resources[role].ProcessRunID
	if start == "" || start != end {
		return nil, fmt.Errorf("%s: process restarted", role)
	}
	withoutStartTime := func(families []*dto.MetricFamily) []*dto.MetricFamily {
		result := make([]*dto.MetricFamily, 0, len(families))
		for _, family := range families {
			if family.GetName() != "process_start_time_seconds" {
				result = append(result, family)
			}
		}
		return result
	}
	return observability.DurationSummaries(withoutStartTime(before.Metrics[role]), withoutStartTime(after.Metrics[role]))
}

func TestSeparatedDurationSummariesUsesProcessRunID(t *testing.T) {
	startFamily := func(value float64) *dto.MetricFamily {
		name := "process_start_time_seconds"
		kind := dto.MetricType_GAUGE
		return &dto.MetricFamily{Name: &name, Type: &kind, Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: &value}}}}
	}
	before := separatedSnapshot{
		Resources: map[string]separatedResources{"ingress-a": {ProcessRunID: "original"}},
		Metrics:   map[string][]*dto.MetricFamily{"ingress-a": {startFamily(100)}},
	}
	after := separatedSnapshot{
		Resources: map[string]separatedResources{"ingress-a": {ProcessRunID: "original"}},
		Metrics:   map[string][]*dto.MetricFamily{"ingress-a": {startFamily(101)}},
	}
	if _, err := separatedDurationSummaries(before, after, "ingress-a"); err != nil {
		t.Fatalf("clock adjustment incorrectly indicated restart: %v", err)
	}
	after.Resources["ingress-a"] = separatedResources{ProcessRunID: "replacement"}
	if _, err := separatedDurationSummaries(before, after, "ingress-a"); err == nil || !strings.Contains(err.Error(), "process restarted") {
		t.Fatalf("missed process restart: %v", err)
	}
}

func separatedReportVisitors(t *testing.T, phase string, results []separatedVisitorResult, restart separatedRestart, repaired time.Time) {
	t.Helper()
	var first, firstExit time.Time
	failures, missed, total, surviving := 0, 0, 0, 0
	var merged benchworkload.VisitorResult
	var successfulDurations []time.Duration
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
				if phase == "control-restart" || phase != "relay-kill" && (runtimeControlledFault(phase) || phase != *runtimeLoadScenario || !row.Started.Before(repaired)) {
					t.Errorf("visitor failed in %s after recovery=%t", phase, !row.Started.Before(repaired))
				}
				continue
			}
			successfulDurations = append(successfulDurations, row.Duration)
			if !row.Started.Before(restart.Started) && (first.IsZero() || row.FirstByte.Before(first)) {
				first = row.FirstByte
			}
			if !row.Started.Before(restart.Exited) && (firstExit.IsZero() || row.FirstByte.Before(firstExit)) {
				firstExit = row.FirstByte
			}
		}
	}
	slices.Sort(successfulDurations)
	var exactP95, exactP99 *float64
	if len(successfulDurations) > 0 {
		p95 := float64(exactLatencyPercentile(successfulDurations, 95)) / float64(time.Millisecond)
		p99 := float64(exactLatencyPercentile(successfulDurations, 99)) / float64(time.Millisecond)
		exactP95, exactP99 = &p95, &p99
	}
	format := func(value *float64) string {
		if value == nil {
			return "unavailable"
		}
		return fmt.Sprintf("%.3fms", *value)
	}
	t.Logf("separated_visitors phase=%s requests=%d success=%d failures=%d missed=%d p50=%s p95=%s p95_exact=%s p99_exact=%s maximum=%.3fms first_body_byte_p95=%s offer=%s drain=%s", phase, total, merged.Successes, failures, missed,
		format(merged.Total.Percentile(50)), format(merged.Total.Percentile(95)), format(exactP95), format(exactP99), merged.Total.MaximumMilliseconds, format(merged.FirstByte.Percentile(95)), merged.OfferDuration, merged.DrainDuration)
	separatedResult(t, phase+"-summary", merged)
	separatedResult(t, phase+"-exact-latency", struct {
		Samples         int      `json:"samples"`
		P95Milliseconds *float64 `json:"p95_milliseconds"`
		P99Milliseconds *float64 `json:"p99_milliseconds"`
	}{len(successfulDurations), exactP95, exactP99})
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

func exactLatencyPercentile(sorted []time.Duration, percentile int) time.Duration {
	return sorted[(len(sorted)*percentile+99)/100-1]
}

func TestExactLatencyPercentileUsesRequestSamples(t *testing.T) {
	var sorted []time.Duration
	for i := 1; i <= 100; i++ {
		sorted = append(sorted, time.Duration(i)*time.Millisecond)
	}
	if got := exactLatencyPercentile(sorted, 95); got != 95*time.Millisecond {
		t.Fatalf("exact p95 = %s", got)
	}
	if got := exactLatencyPercentile(sorted[:21], 95); got != 20*time.Millisecond {
		t.Fatalf("exact p95 for 21 samples = %s", got)
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
			for _, role := range separatedServerRoles() {
				if (phase == "relay-restart" || phase == "relay-kill") && role == "relay-a" || phase == "control-restart" && role == "control-a" {
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
