package state

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	dto "github.com/prometheus/client_model/go"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability"
)

func TestIntegrationOperationMetricsExport(t *testing.T) {
	base := newServicePublicationFixture(t)
	f := base.sibling(t, "metrics", base.now)
	metrics := observability.New("control")
	f.database.Instrument(metrics)
	var err error
	f.prepared, err = f.database.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, "metrics", f.now, ServiceRunRequest{Metadata: f.service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range exportedDurationMetrics(t, metrics) {
		if family.GetName() == "tnl_control_placement_decisions_total" && len(family.Metric) != 0 {
			t.Fatal("preparation reported an uncommitted placement")
		}
	}
	f.run, err = f.database.StartServiceRun(t.Context(), f.service.ID, f.prepared.RunID, f.prepared.RunNumber, f.publisher, f.now)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := f.database.StartServiceRun(t.Context(), f.service.ID, f.prepared.RunID, f.prepared.RunNumber, f.publisher, f.now)
	if err != nil || replayed.RunID != f.run.RunID || replayed.Token != f.run.Token {
		t.Fatal("start replay did not retain its committed run", err)
	}
	installPrivateTestCertificate(t, f.database, f.prepared, f.run, f.now)
	f.readyConnections(t, f.now)
	if _, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.run.ExpiresAt.Add(-time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.run.ExpiresAt.Add(-time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal(err)
	}

	ingress := registerTestIngress(t, f.database, f.now)
	if _, err := f.database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: ingress.IngressLeaseIdentity}, f.now, time.Hour); err != nil {
		t.Fatal(err)
	}

	// validation and pool-acquisition failures belong to the operation even
	// when no SQL has started.
	if _, err := f.database.PrepareServiceRun(t.Context(), "", f.publisher, "bad", f.now, ServiceRunRequest{Metadata: f.service.ServiceMetadata}); err == nil {
		t.Fatal("invalid request succeeded")
	}
	canceledPrep, cancelPrep := context.WithCancel(t.Context())
	cancelPrep()
	if _, err := f.database.PrepareServiceRun(canceledPrep, f.service.ID, f.publisher, "canceled", f.now, ServiceRunRequest{Metadata: f.service.ServiceMetadata}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled prepare: %v", err)
	}
	expiredPrep, stopPrep := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer stopPrep()
	if _, err := f.database.PrepareServiceRun(expiredPrep, f.service.ID, f.publisher, "timeout", f.now, ServiceRunRequest{Metadata: f.service.ServiceMetadata}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired prepare: %v", err)
	}

	canceledHB, cancelHB := context.WithCancel(t.Context())
	cancelHB()
	if _, err := f.database.HeartbeatServiceRun(canceledHB, f.service.ID, f.run.RunID, f.run.Token, f.run.ExpiresAt.Add(-time.Second), ServiceRunHealth{StreamCapacity: 64}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled heartbeat: %v", err)
	}
	expiredHB, stopHB := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer stopHB()
	if _, err := f.database.HeartbeatServiceRun(expiredHB, f.service.ID, f.run.RunID, f.run.Token, f.run.ExpiresAt.Add(-time.Second), ServiceRunHealth{StreamCapacity: 64}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired heartbeat: %v", err)
	}
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}

	families := exportedDurationMetrics(t, metrics)
	for operation, count := range map[string]uint64{
		"CreateServiceRun": 1, "HeartbeatServiceRun": 2, "CloseServiceRun": 1, "RenewIngress": 1,
		"ClaimPublisherConnection": 2, "MarkPublisherConnectionReady": 2,
	} {
		assertDurationCount(t, families, "tnl_control_operation_duration_seconds", operation, "success", count)
	}
	for _, outcome := range []string{"error", "canceled", "timeout"} {
		assertDurationCount(t, families, "tnl_control_operation_duration_seconds", "CreateServiceRun", outcome, 1)
	}
	assertDurationCount(t, families, "tnl_control_operation_duration_seconds", "HeartbeatServiceRun", "canceled", 1)
	assertDurationCount(t, families, "tnl_control_operation_duration_seconds", "HeartbeatServiceRun", "timeout", 1)
	assertDurationCount(t, families, "tnl_database_query_duration_seconds", "SelectServiceForPublisher", "success", 1)
	assertDurationCount(t, families, "tnl_database_query_duration_seconds", "LockRelayServicesForPlacement", "success", 1)
	assertDurationCount(t, families, "tnl_database_guard_held_duration_seconds", "LockRelayServicesForPlacement", "success", 1)

	// preparation and start replay must not count as new committed placements.
	assertCounter(t, families, "tnl_control_placement_decisions_total", map[string]string{
		"tnl_operation": "create", "tnl_outcome": "success", "tnl_reason": "placed",
	}, 1)
}

func TestIntegrationQueryMetricsAndPassiveCollection(t *testing.T) {
	f := newServicePublicationFixture(t)
	database, now := f.database, f.now
	metrics := observability.New("control")
	database.Instrument(metrics)
	metrics.RegisterDatabase(database.PrometheusMetrics)
	if _, err := controlstatedb.New(database.pool).GetService(t.Context(), f.service.ID); err != nil {
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
	if _, err := database.RenewIngress(ctx, IngressRenewal{IngressLeaseIdentity: identity}, now, time.Hour); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("exhausted pool renewal: %v", err)
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
	if response.Code != 200 || !strings.Contains(response.Body.String(), `tnl_database_operations_active{tnl_operation="unknown"} 1`) || strings.Contains(response.Body.String(), "private-query") {
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
	assertDurationCount(t, families, "tnl_database_query_duration_seconds", "GetService", "success", 1)
	assertDurationCount(t, families, "tnl_database_query_duration_seconds", "unknown", "error", 1)
	assertDurationCount(t, families, "tnl_database_query_duration_seconds", "unknown", "canceled", 1)
	assertDurationCount(t, families, "tnl_database_query_duration_seconds", "unknown", "timeout", 1)
	assertDurationCount(t, families, "tnl_control_operation_duration_seconds", "RenewIngress", "timeout", 1)
	var acquireFailures uint64
	for _, family := range families {
		if family.GetName() != "tnl_database_pool_acquire_duration_seconds" {
			continue
		}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() == "tnl_outcome" && label.GetValue() == "timeout" {
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
	database, now := newControlStateIntegrationDatabase(t, "query_delay")
	authority := seedControlServiceAuthority(t, database, now, "guard")
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
	if _, err := controlstatedb.New(tx).LockLocalTeamForSession(t.Context(), authority.TeamID); err != nil {
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
			if labels["tnl_operation"] != operation || labels["tnl_outcome"] != outcome {
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
	t.Fatalf("missing %s{tnl_operation=%q,tnl_outcome=%q}", name, operation, outcome)
	return nil
}

func assertCounter(t *testing.T, families []*dto.MetricFamily, name string, want map[string]string, value float64) {
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
			match := true
			for k, v := range want {
				if labels[k] != v {
					match = false
					break
				}
			}
			if !match || len(labels) != len(want) {
				continue
			}
			if got := metric.GetCounter().GetValue(); got != value {
				t.Fatalf("%s %v=%v, want %v", name, labels, got, value)
			}
			return
		}
	}
	t.Fatalf("missing %s%v", name, want)
}
