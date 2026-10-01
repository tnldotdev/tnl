package tnldruntime

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
	"github.com/tnldotdev/tnl/internal/publisher"
)

func activateSeparatedPublishers(t *testing.T, database *sql.DB, routes int) separatedPublishers {
	t.Helper()
	activationBefore := separatedCapture(t, database, "activation-before")
	activation := time.Now()
	stopTrace := func() {}
	if *runtimeLoadTrace {
		stopTrace = traceRuntimeCertificateState(t, database, activation)
	}
	defer stopTrace()
	separatedWrite(t, "publish.start", activation)
	publishers := separatedPublishers{URLs: make([]string, routes), Ready: make([]publisher.Event, routes)}
	// each publisher retains its own readiness deadline, starting at launch.
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
		waitForReadyPublisherConnections(t, database, ready.PublicURLID, ready.PublishRunNumber, 2)
	}
	waitForIngressRoutingCurrentWithin(t, database, len(separatedIngresses()), separatedRoutingAcknowledgmentTimeout)
	var orders, installed, distinctPublicURLs int
	var workerAttempts int64
	if err := database.QueryRowContext(integrationOperationContext(t), `SELECT count(*), count(*) FILTER (WHERE state = 'installed'), count(DISTINCT public_url_id), coalesce(sum(attempts), 0) FROM control.acme_orders`).Scan(&orders, &installed, &distinctPublicURLs, &workerAttempts); err != nil {
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
	if orders != routes || installed != routes || distinctPublicURLs != routes || caOrders != int64(routes) {
		t.Fatalf("duplicate/incomplete issuance: routes=%d orders=%d installed=%d distinct=%d CA=%d", routes, orders, installed, distinctPublicURLs, caOrders)
	}
	t.Logf("separated_activation_verified routes=%d installed=%d CA_new_orders=%d elapsed=%s", routes, installed, caOrders, activationElapsed)
	return publishers
}

func runSeparatedWorkloadPhases(t *testing.T, database *sql.DB, publishers separatedPublishers, routes int, duration time.Duration, initialFault separatedRestart, sequence int) {
	t.Helper()
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
			// these held streams are opened through the healthy path while the
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
				err := database.QueryRowContext(ctx, `SELECT count(*) FROM control.publish_run_connections WHERE connected_relay_id='relay-a-1' AND state='ready'`).Scan(&count)
				return count == 0, err
			})
			t.Logf("publisher_connection_loss_detected elapsed_since_drop=%s", time.Since(restart.Exited))
		}
		if phase == "relay-kill" {
			var restored time.Time
			separatedWait(t, "fault.restored", 45*time.Second, &restored)
			restart.Restored = restored
			separatedWait(t, "relay-a.restarted", 10*time.Second, nil)
			// a killed relay waits out its 30-second lease. The next 15-second
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
		// cover every live route, not only routes sampled late in a traffic window.
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
}

func verifySeparatedShutdown(t *testing.T, database *sql.DB, routes int) {
	t.Helper()
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
			(SELECT count(*) FROM control.publish_runs WHERE closed_at IS NULL OR assignments_open) +
			(SELECT count(*) FROM control.publish_run_connections WHERE state <> 'closed') +
			(SELECT coalesce(sum(assignment_count), 0) FROM control.relay_service_assignment_totals)`).Scan(&active)
		return active == 0, err
	})
	routingTimeout := separatedRoutingAcknowledgmentTimeout
	if *runtimeLoadCapacityOnly {
		routingTimeout = 30 * time.Second
	}
	waitForIngressRoutingCurrentWithin(t, database, len(separatedIngresses()), routingTimeout)
	separatedCapture(t, database, "final")
	if got := separatedCAOrders(t); got != int64(routes) {
		t.Errorf("certificate issuance changed during workload: got %d want %d", got, routes)
	}
	// stop ingress while control and PostgreSQL remain available. Its production
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
	var buckets, coveredPublicURLs, attempts, successes, ingressBytes, egressBytes int64
	if err := database.QueryRowContext(integrationOperationContext(t), `SELECT count(*), count(DISTINCT public_url_id), coalesce(sum(connection_attempts),0),
		coalesce(sum(successful_streams),0), coalesce(sum(ingress_bytes),0), coalesce(sum(egress_bytes),0) FROM control.public_url_usage_buckets`).Scan(&buckets, &coveredPublicURLs, &attempts, &successes, &ingressBytes, &egressBytes); err != nil {
		t.Fatal(err)
	}
	if coveredPublicURLs != int64(routes) || successes == 0 || egressBytes == 0 {
		t.Error("real visitor usage was not persisted")
	}
	var incomplete, mismatches int
	if err := database.QueryRowContext(integrationOperationContext(t), `SELECT count(*) FROM control.ingress_usage_runs WHERE NOT coverage_complete`).Scan(&incomplete); err != nil || incomplete != 0 {
		t.Fatalf("ingress usage completion: incomplete=%d error=%v", incomplete, err)
	}
	if err := database.QueryRowContext(integrationOperationContext(t), `WITH latest AS (
		SELECT DISTINCT ON (ingress_id, ingress_run_id, public_url_id, publish_run_number, bucket_start) *
		FROM control.ingress_usage_reports ORDER BY ingress_id, ingress_run_id, public_url_id, publish_run_number, bucket_start, report_revision DESC
	), totals AS (
		SELECT public_url_id, publish_run_number, bucket_start, sum(connection_attempts) AS attempts,
		sum(successful_streams) AS successes, sum(ingress_bytes) AS ingress_bytes, sum(egress_bytes) AS egress_bytes
		FROM latest GROUP BY public_url_id, publish_run_number, bucket_start
	) SELECT count(*) FROM totals t FULL JOIN control.public_url_usage_buckets b USING (public_url_id, publish_run_number, bucket_start)
	WHERE t.attempts IS DISTINCT FROM b.connection_attempts OR t.successes IS DISTINCT FROM b.successful_streams
	OR t.ingress_bytes IS DISTINCT FROM b.ingress_bytes OR t.egress_bytes IS DISTINCT FROM b.egress_bytes`).Scan(&mismatches); err != nil || mismatches != 0 {
		t.Fatalf("final usage accounting: mismatches=%d error=%v", mismatches, err)
	}
	t.Logf("separated_verified routes=%d active_sessions=0 active_connections=0 reservations=0 usage_buckets=%d attempts=%d successes=%d ingress_bytes=%d egress_bytes=%d", routes, buckets, attempts, successes, ingressBytes, egressBytes)
}
