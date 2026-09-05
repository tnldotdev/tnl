package controlstate

import (
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	dto "github.com/prometheus/client_model/go"
	"github.com/tnldotdev/tnl/internal/observability"
)

type controlLoadFixture struct {
	database *Database
	now      time.Time
	base     RouteSessionRequest
	routes   int
	history  int
	leases   map[string][]RelayLease
	controls []*Database
	delay    time.Duration
	metrics  []*observability.Metrics
	before   [][]*dto.MetricFamily
}

func newControlLoadFixture(t *testing.T) *controlLoadFixture {
	t.Helper()
	if os.Getenv("TNL_TEST_LOAD") != "1" {
		t.Skip("run task go:test-load")
	}
	delay := time.Duration(0)
	if raw := os.Getenv("TNL_TEST_LOAD_DELAY"); raw != "" {
		var err error
		delay, err = time.ParseDuration(raw)
		if err != nil || delay < 0 || delay > 50*time.Millisecond {
			t.Fatal("query delay must be between 0 and 50ms")
		}
	}
	routes := 1000
	if raw := os.Getenv("TNL_TEST_LOAD_ROUTES"); raw != "" {
		var err error
		routes, err = strconv.Atoi(raw)
		if err != nil || routes <= 0 || int64(routes) > 2147483647 {
			t.Fatal("route count must be a positive PostgreSQL integer")
		}
	}
	history := int64(1)
	if raw := os.Getenv("TNL_TEST_LOAD_HISTORY"); raw != "" {
		var err error
		history, err = strconv.ParseInt(raw, 10, 32)
		if err != nil || history < 1 {
			t.Fatal("history events per route must be a positive PostgreSQL integer")
		}
	}
	database, now, request, originalLeases := newRouteSessionPrerequisites(t)
	f := &controlLoadFixture{database: database, now: now, base: request, routes: routes, history: int(history), leases: make(map[string][]RelayLease)}
	_, err := database.pool.Exec(t.Context(), `
		INSERT INTO control.routes (id, team_id, domain_id, created_by_identity_id, idempotency_key,
			request_digest, canonical_hostname, target, route_scope, policy_revision, ip_policy,
			lifecycle_state, dns_state, created_at, updated_at)
		SELECT 'route_load_' || n, team_id, domain_id, created_by_identity_id, 'load-' || n,
			request_digest, 'load-' || n || '.example.test', target, route_scope, policy_revision,
			ip_policy, lifecycle_state, dns_state, created_at, updated_at
		FROM control.routes CROSS JOIN generate_series(0, $1::integer - 1) AS n WHERE id = $2`, routes, request.RouteID)
	if err != nil {
		t.Fatal(err)
	}
	capacity := max(4096, routes)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.relay_leases SET connection_capacity = $1`, capacity); err != nil {
		t.Fatal(err)
	}
	for service, first := range originalLeases {
		registration := relayLifecycleRegistration(service)
		registration.RelayID, registration.ConnectionCapacity = service+"-2", uint64(capacity)
		second, err := database.RegisterRelay(t.Context(), registration, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		f.leases[service] = []RelayLease{first, second}
	}
	f.delay = delay
	for range 2 {
		metrics := observability.New("control")
		activity, connections := new(queryActivity), new(connectionActivity)
		activity.metrics.Store(metrics)
		config := database.pool.Config()
		config.MaxConns = 8
		config.ConnConfig.RuntimeParams["application_name"] = "tnl-load-test"
		config.ConnConfig.Tracer = &queryDelayTracer{
			connectionTracer: &connectionTracer{connections: connections, purpose: requestPoolConnection, queries: activity}, delay: delay,
		}
		pool, err := pgxpool.NewWithConfig(t.Context(), config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		control := &Database{pool: pool, storageKey: database.storageKey, activity: activity, connections: connections}
		metrics.RegisterDatabase(control.PrometheusMetrics)
		f.controls = append(f.controls, control)
		f.metrics = append(f.metrics, metrics)
		var warm []*pgxpool.Conn
		for range 8 {
			conn, err := pool.Acquire(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			warm = append(warm, conn)
			t.Cleanup(conn.Release)
		}
		for _, conn := range warm {
			conn.Release()
		}
	}
	return f
}

func (f *controlLoadFixture) request(index int) RouteSessionRequest {
	request := f.base
	request.RouteID = fmt.Sprintf("route_load_%d", index)
	request.CertificateIdentifiers = []string{fmt.Sprintf("load-%d.example.test", index)}
	request.CertificateCacheKey = request.CertificateIdentifiers[0]
	return request
}

// Capture after fixture setup, before starting actors. End collection happens
// only after actors join, including failure paths, and before pools close.
func (f *controlLoadFixture) startMetrics(t *testing.T) {
	t.Helper()
	f.before = nil
	for _, metrics := range f.metrics {
		before, err := metrics.Gather()
		if err != nil {
			t.Fatal(err)
		}
		f.before = append(f.before, before)
	}
}

func (f *controlLoadFixture) logStats(t *testing.T) {
	t.Helper()
	t.Logf("routes=%d pools=2x8 extra_query_delay=%s", f.routes, f.delay)
	for index := range f.controls {
		after, err := f.metrics[index].Gather()
		if err != nil {
			t.Error(err)
			continue
		}
		for _, name := range []string{"tnl_database_pool_waited_acquires_total", "tnl_database_pool_canceled_acquires_total", "tnl_database_pool_acquire_wait_seconds_total"} {
			delta := loadCounter(t, after, name) - loadCounter(t, f.before[index], name)
			if delta < 0 {
				t.Errorf("counter reset: control=%d %s", index, name)
			}
			t.Logf("control=%d %s delta=%g", index, name, delta)
		}
		summaries, err := observability.DurationSummaries(f.before[index], after)
		if err != nil {
			t.Error(err)
			continue
		}
		for _, summary := range summaries {
			if summary.Count == 0 {
				continue
			}
			t.Logf("control=%d %s labels=%v calls=%d mean_seconds=%g p50_seconds=%s p95_seconds=%s p99_seconds=%s total_seconds=%g",
				index, summary.Name, summary.Labels, summary.Count, summary.MeanSeconds,
				loadPercentile(summary.P50Seconds), loadPercentile(summary.P95Seconds), loadPercentile(summary.P99Seconds), summary.SumSeconds)
		}
	}
}

func loadCounter(t *testing.T, families []*dto.MetricFamily, name string) float64 {
	t.Helper()
	for _, family := range families {
		if family.GetName() == name && len(family.Metric) == 1 && family.Metric[0].Counter != nil {
			return family.Metric[0].Counter.GetValue()
		}
	}
	t.Fatalf("missing pool counter %s", name)
	return 0
}

func loadPercentile(seconds *float64) string {
	if seconds == nil {
		return "unavailable"
	}
	return strconv.FormatFloat(*seconds, 'g', -1, 64)
}
