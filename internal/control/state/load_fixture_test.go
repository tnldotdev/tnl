package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	dto "github.com/prometheus/client_model/go"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/testutil"
)

var (
	loadDelay      = flag.Duration("tnl-load-delay", 0, "delay after successful database commands")
	loadPublicURLs = flag.Int("tnl-load-public-urls", 1000, "number of public HTTP services in the database load test")
	loadHistory    = flag.Int("tnl-load-history", 1, "warmup heartbeats per ready service")
	loadDuration   = flag.Duration("tnl-load-duration", 0, "paced database load duration")
	loadRetention  = flag.Duration("tnl-load-retention", 0, "service cleanup observation window")
)

type controlLoadFixture struct {
	database   *Database
	now        time.Time
	actorID    string
	base       ServiceRecord
	services   []ServiceRecord
	publishers []PublisherIdentity
	routes     int
	history    int
	leases     map[string][]RelayLease
	controls   []*Database
	delay      time.Duration
	metrics    []*observability.Metrics
	before     [][]*dto.MetricFamily
}

func newControlLoadFixture(t *testing.T) *controlLoadFixture {
	t.Helper()
	testutil.RequireTestTier(t, testutil.TestTierDatabaseLoad)
	if *loadDelay < 0 || *loadDelay > 50*time.Millisecond {
		t.Fatal("query delay must be between 0 and 50ms")
	}
	if *loadPublicURLs <= 0 || int64(*loadPublicURLs) > 2147483647 {
		t.Fatal("service count must be a positive PostgreSQL integer")
	}
	if *loadHistory < 1 || int64(*loadHistory) > 2147483647 {
		t.Fatal("warmup heartbeats per service must be a positive PostgreSQL integer")
	}
	database, now := newControlStateIntegrationDatabase(t, "service_load")
	session := newOIDCSession(t, database, now)
	member, actor := session.Identity.Memberships[0], session.Identity.Identity.ID
	if err := database.EnsurePrimaryIngressPool(t.Context(), "192.0.2.10", "", now); err != nil {
		t.Fatal(err)
	}
	f := &controlLoadFixture{database: database, now: now, actorID: actor, routes: *loadPublicURLs, history: *loadHistory, leases: make(map[string][]RelayLease)}
	capacity := max(4096, *loadPublicURLs)
	for _, service := range []string{"load-a", "load-b"} {
		for process := range 2 {
			registration := relayLifecycleRegistration(service)
			registration.RelayID = fmt.Sprintf("%s-%d", service, process)
			registration.ConnectionCapacity = uint64(capacity)
			lease, err := database.RegisterRelay(t.Context(), registration, now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			f.leases[service] = append(f.leases[service], lease)
		}
	}
	for index := range f.routes {
		name := fmt.Sprintf("load-%d", index)
		service, err := database.CreateServiceAt(t.Context(), member.TeamID, actor, name, name, ServicePlacement{},
			now, ServiceMetadata{}, &ProjectServiceConfiguration{Target: "http://127.0.0.1:3000", Public: new(true)})
		if err != nil {
			t.Fatal(err)
		}
		enrollment, err := database.IssuePublisherEnrollment(t.Context(), CreatePublisherEnrollmentRequest{
			Scope: PublisherScope{TeamID: member.TeamID, Kind: "service", ServiceID: service.ID},
			Name:  "load", Kind: "installed", EditorID: actor, EditorMembershipID: member.ID,
			PolicyRevision: uint64(member.PolicyRevision), Now: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		publisher, err := database.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
		if err != nil {
			t.Fatal(err)
		}
		f.services, f.publishers = append(f.services, service), append(f.publishers, publisher)
	}
	f.base = f.services[0]
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

func (f *controlLoadFixture) request(index int) ServiceRunRequest {
	return ServiceRunRequest{Metadata: f.services[index].ServiceMetadata}
}

func readLoadAdmission(ctx context.Context, control *Database, ingress IngressLeaseIdentity, session servicePublicationFixture, now time.Time) (admission PublicServiceVisitorAdmission, result error) {
	visitor, err := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	if err != nil {
		return admission, err
	}
	admission, err = control.AdmitPublicServiceVisitor(ctx, ingress, PrimaryIngressPoolID, visitor,
		session.service.Endpoint.Hostname, 443, netip.MustParseAddr("192.0.2.10"), now)
	if err != nil {
		return admission, err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		result = errors.Join(result, control.ClosePublicServiceVisitor(cleanup, ingress, visitor, now))
	}()
	if admission.ServiceID != session.service.ID || admission.RunID != session.run.RunID || admission.RunNumber != session.run.RunNumber ||
		!admission.ExpiresAt.After(now) || len(admission.Relays) < 1 || len(admission.Relays) > 2 {
		return admission, fmt.Errorf("admission lost current service run %s", session.service.ID)
	}
	status, err := control.PublicServiceVisitorStatus(ctx, ingress, visitor, now)
	if err != nil || status.State != PublicServiceVisitorPending || !status.ValidUntil.Equal(admission.ExpiresAt) {
		return admission, fmt.Errorf("admission changed pending deadline for service %s: %v", session.service.ID, err)
	}
	return admission, nil
}

// capture after fixture setup, before starting actors. end collection happens
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
	t.Logf("services=%d pools=2x8 extra_query_delay=%s", f.routes, f.delay)
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
