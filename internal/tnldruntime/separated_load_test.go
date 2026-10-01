package tnldruntime

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
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
	runtimeLoadPublicURLs         = flag.Int("tnl-runtime-load-public-urls", 4, "runtime load public URL count")
	runtimeLoadStartParallel      = flag.Int("tnl-runtime-load-start-parallel", 4, "maximum concurrently activating publishers (1-1000)")
	runtimeLoadReadyTimeout       = flag.Duration("tnl-runtime-load-ready-timeout", 30*time.Second, "publisher readiness timeout (30s-5m)")
	runtimeLoadCertificateWorkers = flag.Int("tnl-runtime-load-public-url-certificate-workers", 8, "public URL certificate workers per control process (1-8)")
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
			(SELECT jsonb_agg(jsonb_build_object('state', state, 'public_url_id', public_url_id, 'version', publish_run_number, 'expires_at', publisher_expires_at)) FROM control.publish_runs),
			'orders', (SELECT jsonb_agg(jsonb_build_object('state', state, 'public_url_id', public_url_id, 'attempts', attempts, 'available_at', available_at, 'claimed', work_owner IS NOT NULL, 'last_error', last_error)) FROM control.acme_orders))::text`).Scan(&states)
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
	publishers := activateSeparatedPublishers(t, database, routes)
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
	runSeparatedWorkloadPhases(t, database, publishers, routes, duration, initialFault, sequence)
	verifySeparatedShutdown(t, database, routes)
}

func separatedLoadParameters(t *testing.T) (int, int, time.Duration) {
	t.Helper()
	// validate admission inputs with the production configuration rules before
	// any component starts work, including the coordinator and visitors.
	separatedConfig(t, "ingress-a")
	routes, rate, duration := *runtimeLoadPublicURLs, *runtimeLoadRPS, *runtimeLoadDuration
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
		t.Fatal("public URL certificate workers must be between 1 and 8")
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

func assertSeparatedNoRejections(t *testing.T, phase string, before, after separatedSnapshot) {
	t.Helper()
	for _, role := range append(separatedIngresses(), "relay-a", "relay-b") {
		for _, name := range []string{"tnl_admission_rejections_total"} {
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
				if family.GetName() != "tnl_ingress_operation_duration_seconds" {
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

// the observer's process run ID is stable across clock adjustments. on Docker
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

// sample production freshness, connection, and stream gauges during traffic rather than
// inferring their peaks from the idle phase endpoints. raw endpoint scrapes retain
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
					if !strings.HasPrefix(name, "tnl_ingress_routing_") && name != "tnl_ingress_backend_streams" && name != "tnl_relay_visitor_stream_slots_occupied" && name != "tnl_relay_publisher_connections_ready" && name != "tnl_ingress_connections" && name != "tnl_database_pool_acquired_connections" {
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
