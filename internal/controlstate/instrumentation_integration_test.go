package controlstate

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	dto "github.com/prometheus/client_model/go"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/publicurlusage"
)

func TestIntegrationOperationMetricsExport(t *testing.T) {
	database, now, request, leases := newPublishRunPrerequisites(t)
	metrics := observability.New("control")
	database.Instrument(metrics)
	setup, err := database.CreatePublishRun(t.Context(), request, now, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f := publishRunFixture{database, now, request, setup, leases}
	readyTestSession(t, f)
	if _, err := database.HeartbeatPublishRun(t.Context(), f.authentication(), now.Add(time.Second), time.Hour, time.Hour); err != nil {
		t.Fatal(err)
	}
	ingress := registerTestIngress(t, database, now)
	if _, err := database.ReadIngressRoutingTableSnapshot(t.Context(), ingress.IngressLeaseIdentity, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ReadIngressRoutingTableEvents(t.Context(), ingress.IngressLeaseIdentity, 0, 100, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: ingress.IngressLeaseIdentity}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := database.ReportIngressUsage(t.Context(), ingress.IngressLeaseIdentity, IngressUsageBatch{Reports: []IngressUsageReport{{
		PublicURLID: setup.PublicURLID, PublishRunNumber: setup.PublishRunNumber, ReportRevision: 1,
		BucketStart: now.Truncate(time.Minute), BucketEnd: now.Truncate(time.Minute).Add(time.Minute), ObservedThrough: now,
		HistogramData: (publicurlusage.Checkpoint{}).MarshalBinary(),
	}}}, now); err != nil {
		t.Fatal(err)
	}
	// validation and pool-acquisition failures belong to the state operation,
	// even when no SQL has started.
	if _, err := database.CreatePublishRun(t.Context(), PublishRunRequest{}, now, time.Hour, time.Hour); err == nil {
		t.Fatal("invalid request succeeded")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := database.CreatePublishRun(canceled, request, now, time.Hour, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled create: %v", err)
	}
	expired, stop := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer stop()
	if _, err := database.CreatePublishRun(expired, request, now, time.Hour, time.Hour); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired create: %v", err)
	}
	families := exportedDurationMetrics(t, metrics)
	for operation, count := range map[string]uint64{
		"CreatePublishRun": 1, "HeartbeatPublishRun": 1, "ClaimPublisherConnection": 2,
		"MarkPublisherConnectionReady": 2, "ReadIngressRoutingTableSnapshot": 1,
		"ReadIngressRoutingTableEvents": 1, "RenewIngress": 1, "ReportIngressUsage": 1,
	} {
		assertDurationCount(t, families, "tnl_control_operation_duration_seconds", operation, "success", count)
	}
	for _, outcome := range []string{"error", "canceled", "deadline_exceeded"} {
		assertDurationCount(t, families, "tnl_control_operation_duration_seconds", "CreatePublishRun", outcome, 1)
	}
	assertDurationCount(t, families, "tnl_database_query_duration_seconds", "ListIngressRoutingTableSnapshot", "success", 1)
	assertDurationCount(t, families, "tnl_database_guard_held_duration_seconds", "LockLocalTeamForSession", "success", 1)
	assertDurationCount(t, families, "tnl_database_guard_held_duration_seconds", "LockRelayServicesForPlacement", "success", 1)
	assertDurationCount(t, families, "tnl_database_guard_held_duration_seconds", "LockPublishRunForUsage", "success", 1)
	var placements float64
	for _, family := range families {
		if family.GetName() != "tnl_control_placement_decisions_total" {
			continue
		}
		for _, metric := range family.Metric {
			if len(metric.Label) == 2 && metric.Label[0].GetValue() == "create" && metric.Label[1].GetValue() == "placed" {
				placements += metric.GetCounter().GetValue()
			}
		}
	}
	if placements != 1 {
		t.Fatalf("committed create placements=%g, want 1", placements)
	}
}

func TestIntegrationQueryMetricsAndPassiveCollection(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "query_metrics")
	metrics := observability.New("control")
	database.Instrument(metrics)
	metrics.RegisterDatabase(database.PrometheusMetrics)
	if _, err := controlstatedb.New(database.pool).ReadIngressRoutingTableClock(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), "SELECT 1/0 /* private-query */"); err == nil {
		t.Fatal("SQL error expected")
	}
	// retain every pool slot, then exercise a state operation that times out
	// acquiring one. export must still complete without a connection or query.
	var held []*pgxpool.Conn
	defer func() {
		for _, conn := range held {
			conn.Release()
		}
	}()
	for range database.pool.Config().MaxConns {
		conn, err := database.pool.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
	}
	queryCtx, stopQuery := context.WithCancel(t.Context())
	workers := newIntegrationWorkers(t, stopQuery)
	defer workers.stop()
	queryDone := make(chan error, 1)
	workers.Go(func() {
		_, err := held[0].Exec(queryCtx, "SELECT pg_sleep(30) /* private-query */")
		queryDone <- err
	})
	waitCtx, stopWaiting := context.WithTimeout(t.Context(), time.Second)
	defer stopWaiting()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		active, _ := database.activity.snapshot(time.Now())
		if len(active) == 1 && active[0].Operation == "unknown" {
			break
		}
		select {
		case <-tick.C:
		case err := <-queryDone:
			t.Fatalf("query ended before passive scrape: %v", err)
		case <-waitCtx.Done():
			t.Fatal("query never became active")
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	identity := IngressLeaseIdentity{IngressID: "ingress_test", IngressRunID: "run_test", IngressLeaseRevision: 1}
	if _, err := database.ReadIngressRoutingTableSnapshot(ctx, identity, time.Now()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("exhausted pool read: %v", err)
	}
	before := database.PoolStats()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		metrics.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
		done <- response
	}()
	var response *httptest.ResponseRecorder
	select {
	case response = <-done:
	case <-time.After(time.Second):
		t.Fatal("metrics collection blocked on exhausted pool")
	}
	if response.Code != 200 || !strings.Contains(response.Body.String(), `tnl_database_operations_active{operation="unknown"} 1`) || strings.Contains(response.Body.String(), "private-query") {
		t.Fatalf("passive scrape did not expose safe active-query state: status=%d", response.Code)
	}
	after := database.PoolStats()
	if before.AcquireCount() != after.AcquireCount() || before.TotalConns() != after.TotalConns() || after.AcquiredConns() != after.MaxConns() {
		t.Fatal("metrics collection acquired or opened a connection")
	}
	stopQuery()
	if err := awaitIntegrationResult(t, waitCtx, queryDone); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled SQL: %v", err)
	}
	workers.Wait()
	deadlineCtx, stopDeadline := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer stopDeadline()
	if _, err := held[1].Exec(deadlineCtx, "SELECT pg_sleep(30) /* private-query */"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline SQL: %v", err)
	}
	families := exportedDurationMetrics(t, metrics)
	assertDurationCount(t, families, "tnl_database_query_duration_seconds", "ReadIngressRoutingTableClock", "success", 1)
	assertDurationCount(t, families, "tnl_database_query_duration_seconds", "unknown", "error", 1)
	assertDurationCount(t, families, "tnl_database_query_duration_seconds", "unknown", "canceled", 1)
	assertDurationCount(t, families, "tnl_database_query_duration_seconds", "unknown", "deadline_exceeded", 1)
	assertDurationCount(t, families, "tnl_control_operation_duration_seconds", "ReadIngressRoutingTableSnapshot", "deadline_exceeded", 1)
	var acquireFailures uint64
	for _, family := range families {
		if family.GetName() != "tnl_database_pool_acquire_duration_seconds" {
			continue
		}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() == "outcome" && label.GetValue() == "deadline_exceeded" {
					acquireFailures += metric.GetHistogram().GetSampleCount()
				}
			}
		}
	}
	if acquireFailures == 0 {
		t.Fatal("pool exhaustion did not emit acquire timeout")
	}
}

func TestIntegrationQueryDelayPreservesProductionGuardWindow(t *testing.T) {
	database, _, request, _ := newPublishRunPrerequisites(t)
	metrics := observability.New("control")
	activity := new(queryActivity)
	activity.metrics.Store(metrics)
	const delay = 10 * time.Millisecond
	config := database.pool.Config()
	config.ConnConfig.Tracer = &queryDelayTracer{connectionTracer: &connectionTracer{queries: activity}, delay: delay}
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	started := time.Now()
	if _, err := controlstatedb.New(tx).LockLocalTeamForSession(t.Context(), request.TeamID); err != nil {
		t.Fatal(err)
	}
	queryElapsed := time.Since(started)
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	families := exportedDurationMetrics(t, metrics)
	query := assertDurationCount(t, families, "tnl_database_query_duration_seconds", "LockLocalTeamForSession", "success", 1)
	guard := assertDurationCount(t, families, "tnl_database_guard_held_duration_seconds", "LockLocalTeamForSession", "success", 1)
	if queryElapsed.Seconds()-query.GetSampleSum() < delay.Seconds() || guard.GetSampleSum() < delay.Seconds() {
		t.Fatalf("query delay included in SQL or omitted from guard: query=%v wall=%s guard=%v", query, queryElapsed, guard)
	}
}

func exportedDurationMetrics(t *testing.T, metrics *observability.Metrics) []*dto.MetricFamily {
	t.Helper()
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	if response.Code != 200 || strings.Contains(response.Body.String(), "private-query") {
		t.Fatalf("invalid or unsafe metrics response: %d", response.Code)
	}
	families, err := observability.ParseMetrics(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return families
}

func assertDurationCount(t *testing.T, families []*dto.MetricFamily, name, operation, outcome string, count uint64) *dto.Histogram {
	t.Helper()
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			labels := make(map[string]string)
			for _, label := range metric.Label {
				labels[label.GetName()] = label.GetValue()
			}
			if labels["operation"] != operation || labels["outcome"] != outcome {
				continue
			}
			h := metric.GetHistogram()
			if len(labels) != 2 || h.GetSampleCount() != count || h.GetSampleSum() <= 0 {
				t.Fatalf("%s %v: got %v, want count=%d", name, labels, h, count)
			}
			bounds := observability.DurationBucketsSeconds()
			// parsed exposition also contains the implicit +Inf bucket.
			if len(h.Bucket) != len(bounds)+1 {
				t.Fatalf("%s buckets=%v", name, h.Bucket)
			}
			for index, bound := range bounds {
				if h.Bucket[index].GetUpperBound() != bound {
					t.Fatalf("%s boundary=%g want=%g", name, h.Bucket[index].GetUpperBound(), bound)
				}
			}
			return h
		}
	}
	t.Fatalf("missing %s{operation=%q,outcome=%q}", name, operation, outcome)
	return nil
}
