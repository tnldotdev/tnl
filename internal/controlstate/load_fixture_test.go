package controlstate

import (
	"flag"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	dto "github.com/prometheus/client_model/go"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/testutil"
)

var (
	loadDelay      = flag.Duration("tnl-load-delay", 0, "delay after successful database commands")
	loadPublicURLs = flag.Int("tnl-load-public-urls", 1000, "number of public URLs in the database load test")
	loadHistory    = flag.Int("tnl-load-history", 1, "initial routing events per route")
	loadDuration   = flag.Duration("tnl-load-duration", 0, "paced database load duration")
	loadRetention  = flag.Duration("tnl-load-retention", 0, "routing history retention window")
)

type controlLoadFixture struct {
	database *Database
	now      time.Time
	base     PublishRunRequest
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
	testutil.RequireTestTier(t, testutil.TestTierDatabaseLoad)
	if *loadDelay < 0 || *loadDelay > 50*time.Millisecond {
		t.Fatal("query delay must be between 0 and 50ms")
	}
	if *loadPublicURLs <= 0 || int64(*loadPublicURLs) > 2147483647 {
		t.Fatal("route count must be a positive PostgreSQL integer")
	}
	if *loadHistory < 1 || int64(*loadHistory) > 2147483647 {
		t.Fatal("history events per route must be a positive PostgreSQL integer")
	}
	database, now, request, originalLeases := newPublishRunPrerequisites(t)
	f := &controlLoadFixture{database: database, now: now, base: request, routes: *loadPublicURLs, history: *loadHistory, leases: make(map[string][]RelayLease)}
	_, err := database.pool.Exec(t.Context(), `
		INSERT INTO control.public_urls (id, team_id, domain_id, created_by_identity_id, idempotency_key,
			request_digest, canonical_hostname, target, public_url_scope, policy_revision, ip_policy,
			lifecycle_state, dns_state, created_at, updated_at)
		SELECT 'public_url_load_' || n, team_id, domain_id, created_by_identity_id, 'load-' || n,
			request_digest, 'load-' || n || '.example.test', target, public_url_scope, policy_revision,
			ip_policy, lifecycle_state, dns_state, created_at, updated_at
		FROM control.public_urls CROSS JOIN generate_series(0, $1::integer - 1) AS n WHERE id = $2`, *loadPublicURLs, request.PublicURLID)
	if err != nil {
		t.Fatal(err)
	}
	capacity := max(4096, *loadPublicURLs)
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
	f.delay = *loadDelay
	for range 2 {
		metrics := observability.New("control")
		activity, connections := new(queryActivity), new(connectionActivity)
		activity.metrics.Store(metrics)
		config := database.pool.Config()
		config.MaxConns = 8
		config.ConnConfig.RuntimeParams["application_name"] = "tnl-load-test"
		config.ConnConfig.Tracer = &queryDelayTracer{
			connectionTracer: &connectionTracer{connections: connections, purpose: requestPoolConnection, queries: activity}, delay: *loadDelay,
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

func (f *controlLoadFixture) request(index int) PublishRunRequest {
	request := f.base
	request.PublicURLID = fmt.Sprintf("public_url_load_%d", index)
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
