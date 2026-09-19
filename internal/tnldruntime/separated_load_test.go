package tnldruntime

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/testutil"
)

type separatedSnapshot struct {
	Resources map[string]separatedResources
	Metrics   map[string][]*dto.MetricFamily `json:"-"`
}

func TestLoadSeparatedRuntime(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierSeparatedLoad)
	if *separatedComponent != "coordinator" {
		t.Skip("run task go:test:load:runtime:separated")
	}
	routes, rate, duration := separatedLoadParameters(t)
	database := inspectStandaloneTestDatabase(t, testutil.PostgresURL(t))
	t.Logf("separated_load routes=%d rps=%d sources=4 workers=8 queue=8 payload=32768 phase_duration=%s", routes, rate, duration)
	defer func() {
		if !t.Failed() {
			return
		}
		var states string
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err := database.QueryRowContext(ctx, `SELECT jsonb_build_object('sessions',
			(SELECT jsonb_agg(jsonb_build_object('state', state, 'route_id', route_id, 'version', route_version, 'expires_at', publisher_expires_at)) FROM control.route_sessions),
			'orders', (SELECT jsonb_agg(jsonb_build_object('state', state, 'route_id', route_id, 'attempts', attempts, 'available_at', available_at, 'claimed', work_owner IS NOT NULL)) FROM control.acme_orders))::text`).Scan(&states)
		t.Logf("separated_failure_state=%s error=%v", states, err)
	}()
	for _, name := range []string{"control", "ingress", "relay-a", "relay-b", "app", "pebble"} {
		separatedWait(t, name+".ready", 30*time.Second, nil)
	}
	activation := time.Now()
	separatedWrite(t, "publish.start", activation)
	var publishers separatedPublishers
	// Publishers keep the existing individual 30s checks. This only bounds the
	// whole sequence of four-publisher groups, including IPC and inspection.
	separatedWait(t, "publishers.ready", time.Duration((routes+3)/4)*30*time.Second+10*time.Second, &publishers)
	if len(publishers.Ready) != routes {
		t.Fatal("publisher count mismatch")
	}
	for _, ready := range publishers.Ready {
		waitForReadyPublisherConnections(t, database, ready.RouteID, ready.RouteVersion, 2)
	}
	waitForIngressRoutingCurrent(t, database, 1)
	var orders, installed, distinctRoutes int
	if err := database.QueryRowContext(integrationOperationContext(t), `SELECT count(*), count(*) FILTER (WHERE state = 'installed'), count(DISTINCT route_id) FROM control.acme_orders`).Scan(&orders, &installed, &distinctRoutes); err != nil {
		t.Fatal(err)
	}
	caOrders := separatedResource(t, "control").CAOrders
	if orders != routes || installed != routes || distinctRoutes != routes || caOrders != int64(routes) {
		t.Fatalf("duplicate/incomplete issuance: routes=%d orders=%d installed=%d distinct=%d CA=%d", routes, orders, installed, distinctRoutes, caOrders)
	}
	t.Logf("separated_activation_verified routes=%d installed=%d CA_new_orders=%d elapsed=%s", routes, installed, caOrders, time.Since(activation))
	separatedWrite(t, "visitors.start", time.Now())
	for i := 1; i <= 4; i++ {
		separatedWait(t, fmt.Sprintf("visitor-%d.ready", i), 15*time.Second, nil)
	}
	for _, phase := range []string{"steady", "relay-restart", "shutdown"} {
		before := separatedCapture(t, database, phase+"-before")
		stopSamples := sampleSeparatedGauges(t, phase)
		start := time.Now().Add(time.Second)
		separatedWrite(t, phase+".start", start)
		waitUntilIntegrationTime(t, start.Add(time.Second))
		var restart separatedRestart
		var repaired time.Time
		switch phase {
		case "relay-restart":
			separatedWrite(t, "relay-a.restart", time.Now())
			separatedWait(t, "relay-a.stopped", 10*time.Second, &restart)
			separatedWait(t, "relay-a.restarted", 10*time.Second, nil)
			waitForIntegrationCondition(t, 25*time.Second, func(ctx context.Context) (bool, error) {
				var count int
				err := database.QueryRowContext(ctx, `SELECT count(*) FROM control.route_session_connections c
					JOIN control.relay_leases l ON l.relay_id = c.connected_relay_id AND l.relay_run_id = c.connected_relay_run_id
					AND l.relay_lease_revision = c.connected_relay_lease_revision
					WHERE c.state = 'ready' AND NOT l.draining AND l.lease_expires_at > now()`).Scan(&count)
				return count == routes*2, err
			})
			waitForIngressRoutingCurrent(t, database, 1)
			repaired = time.Now()
			for _, ready := range publishers.Ready {
				assertRouteVersion(t, database, ready.RouteID, ready.RouteVersion)
			}
		case "shutdown":
			separatedWrite(t, "close-half", time.Now())
			var elapsed time.Duration
			separatedWait(t, "close-half.done", time.Duration((routes/2+3)/4)*10*time.Second, &elapsed)
			t.Logf("separated_partial_shutdown publishers=%d elapsed=%s", routes/2, elapsed)
		}
		waitUntilIntegrationTime(t, start.Add(duration))
		// A future shared stop time avoids adding the file-poll delay to each
		// generator's offered schedule. IPC is outside the request retry budget.
		stop := time.Now().Add(300 * time.Millisecond)
		separatedWrite(t, phase+".stop", stop)
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
		if err := os.WriteFile(filepath.Join("/results", phase+"-visitors.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
		after := separatedCapture(t, database, phase+"-after")
		separatedReportResources(t, phase, before, after)
		separatedReportVisitors(t, phase, results, restart, repaired)
	}
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
	routes, rate, duration := *runtimeLoadRoutes, *runtimeLoadRPS, *runtimeLoadDuration
	if routes < 4 || routes > 128 {
		t.Fatal("separated runtime load routes must be between 4 and 128")
	}
	if rate < 4 || rate > 500 {
		t.Fatal("separated runtime load requests per second must be between 4 and 500")
	}
	if duration < 10*time.Second || duration > 2*time.Minute {
		t.Fatal("separated runtime load phase duration must be between 10s and 2m")
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
		if err := os.WriteFile(filepath.Join("/results", name+"-"+role+".prom"), data, 0o600); err != nil {
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
	if err := os.WriteFile(filepath.Join("/results", name+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return result
}

func separatedReportResources(t *testing.T, phase string, before, after separatedSnapshot) {
	t.Helper()
	for _, component := range append(slices.Clone(separatedComponents), "postgres", "coordinator") {
		a, b := before.Resources[component], after.Resources[component]
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
		if role == "relay-a" && phase == "relay-restart" {
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
	var durations []time.Duration
	var firstBytes []time.Duration
	var first, firstExit time.Time
	failures, missed, total, surviving := 0, 0, 0, 0
	for _, result := range results {
		missed += result.Missed
		surviving += result.HeldSurviving
		for _, row := range result.Requests {
			total++
			if row.Error != "" {
				failures++
				if failures <= 3 {
					t.Logf("separated_request_failure phase=%s started=%s error=%s", phase, row.Started, row.Error)
				}
				if phase != "relay-restart" || !row.Started.Before(repaired) {
					t.Errorf("visitor failed in %s after recovery=%t", phase, !row.Started.Before(repaired))
				}
				continue
			}
			durations = append(durations, row.Duration)
			firstBytes = append(firstBytes, row.FirstByte.Sub(row.Started))
			if !row.Started.Before(restart.Started) && (first.IsZero() || row.FirstByte.Before(first)) {
				first = row.FirstByte
			}
			if !row.Started.Before(restart.Exited) && (firstExit.IsZero() || row.FirstByte.Before(firstExit)) {
				firstExit = row.FirstByte
			}
		}
	}
	slices.Sort(durations)
	slices.Sort(firstBytes)
	t.Logf("separated_visitors phase=%s requests=%d success=%d failures=%d missed=%d p50=%s p95=%s maximum=%s first_body_byte_p95=%s", phase, total, len(durations), failures, missed,
		runtimeLoadQuantile(durations, .5), runtimeLoadQuantile(durations, .95), runtimeLoadQuantile(durations, 1), runtimeLoadQuantile(firstBytes, .95))
	if missed != 0 || total == 0 {
		t.Errorf("phase %s: missed=%d requests=%d", phase, missed, total)
	}
	if phase == "relay-restart" {
		if first.IsZero() || firstExit.IsZero() {
			t.Error("no successful visitor during recovery")
		}
		t.Logf("separated_recovery first_body_after_stop=%s first_body_after_exit=%s runtime_exit=%s all_connections_repaired=%s held_surviving=%d", first.Sub(restart.Started), firstExit.Sub(restart.Exited), restart.Exited.Sub(restart.Started), repaired.Sub(restart.Started), surviving)
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
				if phase == "relay-restart" && role == "relay-a" {
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
