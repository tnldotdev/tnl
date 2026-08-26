package controlstate

import (
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type controlLoadFixture struct {
	database *Database
	now      time.Time
	base     RouteSessionRequest
	routes   int
	leases   map[string][]RelayLease
	controls []*Database
	trace    *placementLoadTrace
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
	database, now, request, originalLeases := newRouteSessionPrerequisites(t)
	f := &controlLoadFixture{database: database, now: now, base: request, routes: routes, leases: make(map[string][]RelayLease)}
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
	f.trace = &placementLoadTrace{queryActivity: new(queryActivity), delay: delay, stats: make(map[string]placementLoadStat), held: make(map[*pgx.Conn]map[string]time.Time)}
	for range 2 {
		config := database.pool.Config()
		config.MaxConns = 8
		config.ConnConfig.RuntimeParams["application_name"] = "tnl-load-test"
		config.ConnConfig.Tracer = f.trace
		pool, err := pgxpool.NewWithConfig(t.Context(), config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		f.controls = append(f.controls, &Database{pool: pool, storageKey: database.storageKey})
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

func (f *controlLoadFixture) logStats(t *testing.T) {
	t.Helper()
	f.trace.mu.Lock()
	defer f.trace.mu.Unlock()
	t.Logf("routes=%d pools=2x8 extra_query_delay=%s commands_total=%d", f.routes, f.trace.delay, f.trace.commands)
	for index, control := range f.controls {
		stat := control.PoolStats()
		t.Logf("pool=%d waited_total=%d canceled_total=%d wait_total=%s", index, stat.EmptyAcquireCount(), stat.CanceledAcquireCount(), stat.EmptyAcquireWaitTime())
	}
	for _, name := range []string{"LockLocalTeamForSession", "LockRelayServicesForPlacement", "GetRelayLeaseForClaim", "LockIngressRoutingTableClock", "LockRouteSessionForUsage", "LockIngressLease", "CountOpenRouteSessionAssignmentsByRelayService", "CountRelayActiveConnections", "held:LockLocalTeamForSession", "held:LockRelayServicesForPlacement", "held:GetRelayLeaseForClaim", "held:LockIngressRoutingTableClock", "held:LockRouteSessionForUsage", "held:LockIngressLease", "hostname_lookup", "heartbeat", "usage_page", "ingress_renewal", "routing_events", "routing_snapshot"} {
		stat := f.trace.stats[name]
		if stat.count > 0 {
			t.Logf("%s calls=%d mean=%s max=%s total=%s", name, stat.count, stat.total/time.Duration(stat.count), stat.maximum, stat.total)
		}
	}
}
