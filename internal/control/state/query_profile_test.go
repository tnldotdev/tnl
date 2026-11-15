package state

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// profiles are explicitly selected with RUN=^TestProfile. they use the load
// fixture, but measure isolated SQL plans, not the concurrent load workload.
func TestProfilePlacementQueries(t *testing.T) {
	f := newControlLoadFixture(t)
	if f.delay != 0 {
		t.Fatal("query profiles require DELAY=0ms")
	}
	p := &loadQueryPlan{DBTX: f.database.pool}
	queries := controlstatedb.New(p)
	for index := range f.routes {
		session := servicePublicationFixture{database: f.database, service: f.services[index], publisher: f.publishers[index]}
		session.start(t, "profile", f.now)
		if len(session.run.Connections) != 2 {
			t.Fatal("placement did not allocate two connection slots")
		}
		count := index + 1
		if count != 1000 && count != 2500 && count != f.routes {
			continue
		}
		if _, err := f.database.pool.Exec(t.Context(), "ANALYZE control.service_runs; ANALYZE control.service_connection_slots; ANALYZE control.relay_service_reservations"); err != nil {
			t.Fatal(err)
		}
		rows, err := queries.ListRelayServiceAssignmentTotals(t.Context())
		if err != nil || len(rows) != 2 {
			t.Fatalf("assignment counts: services=%d: %v", len(rows), err)
		}
		for _, row := range rows {
			if row.AssignmentCount != int64(count) {
				t.Fatalf("service=%s assignments=%d want=%d", row.RelayServiceID, row.AssignmentCount, count)
			}
		}
		t.Logf("services=%d assignments=%d (production placement totals)", count, 2*count)
		p.explain(t)
		assertAssignmentTotals(t, f.database.pool, int64(count)*2)
	}
}

func TestProfileRoutingHistory(t *testing.T) {
	f := newControlLoadFixture(t)
	if f.delay != 0 {
		t.Fatal("query profiles require DELAY=0ms")
	}
	sessions := readySteadyLoadSessions(t, f)
	ingress, err := f.database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "profile-ingress", IngressRunID: "profile-run", ProtocolVersion: 1,
		HTTPS: true, IngressPoolID: PrimaryIngressPoolID, ConnectionCapacity: uint64(max(64, f.routes)),
	}, f.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// retain the selector and 4/10/100 update stages, but measure current
	// admission after real heartbeats rather than a retired history projection.
	previous := f.history
	for _, perService := range []int{4, 10, 100} {
		for _, session := range sessions {
			for round := previous; round < perService; round++ {
				run, err := f.database.HeartbeatServiceRun(t.Context(), session.service.ID, session.run.RunID, session.run.Token,
					f.now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
				if err != nil || run.RunID != session.run.RunID || run.RunNumber != session.run.RunNumber || run.State != "ready" {
					t.Fatal("profile warmup changed the current run", err)
				}
			}
		}
		func() {
			f.startMetrics(t)
			defer f.logStats(t)
			for trial := range 3 {
				started := time.Now()
				for _, session := range sessions {
					ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
					err := observeLoadService(ctx, f.controls[trial%2], ingress.IngressLeaseIdentity, session, f.now)
					cancel()
					if err != nil {
						t.Fatal("profile current admission", err)
					}
				}
				t.Logf("warmup_heartbeats_per_service=%d admission_trial=%d admissions=%d elapsed=%s", max(previous, perService), trial+1, len(sessions), time.Since(started))
			}
		}()
		tx, err := f.database.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackTestTransaction(t, tx)
		p := &loadQueryPlan{DBTX: tx}
		traced := &loadQueryTransaction{Tx: tx, plan: p}
		session := sessions[0]
		id, number, until, err := selectRoutableServiceRun(t.Context(), traced, session.service.ID, session.service.Endpoint.Hostname, f.now)
		if err != nil || id != session.run.RunID || number != session.run.RunNumber || !until.After(f.now) {
			_ = tx.Rollback(t.Context())
			t.Fatal("profile selection lost the current run", err)
		}
		p.explain(t)
		relays, _, err := privateConnectedRelays(t.Context(), traced, session.run.RunID, f.now)
		if err != nil || len(relays) != 2 {
			_ = tx.Rollback(t.Context())
			t.Fatal("profile current connected relays", err)
		}
		p.explain(t)
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
		previous = max(previous, perService)
	}
}

// record the actual sqlc query and its parameters instead of maintaining a
// second copy of production SQL in a profiling fixture. calls are serial.
type loadQueryPlan struct {
	controlstatedb.DBTX
	sql  string
	args []any
}

func (p *loadQueryPlan) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	p.sql, p.args = sql, args
	return p.DBTX.Exec(ctx, sql, args...)
}

type loadQueryTransaction struct {
	pgx.Tx
	plan *loadQueryPlan
}

func (p *loadQueryTransaction) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return p.plan.Query(ctx, sql, args...)
}

func (p *loadQueryTransaction) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return p.plan.QueryRow(ctx, sql, args...)
}

func (p *loadQueryPlan) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	p.sql, p.args = sql, args
	return p.DBTX.Query(ctx, sql, args...)
}

func (p *loadQueryPlan) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	p.sql, p.args = sql, args
	return p.DBTX.QueryRow(ctx, sql, args...)
}

func (p *loadQueryPlan) explain(t *testing.T) {
	t.Helper()
	for trial := range 3 {
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		// EXPLAIN ANALYZE executes writes. isolate each trial so it sees the
		// same rows and never changes the workload being measured.
		tx, transactional := p.DBTX.(pgx.Tx)
		if transactional {
			if _, err := tx.Exec(ctx, "SAVEPOINT profile_trial"); err != nil {
				cancel()
				t.Fatal(err)
			}
		}
		rows, err := p.DBTX.Query(ctx, "EXPLAIN (ANALYZE, BUFFERS, SETTINGS) "+p.sql, p.args...)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		var plan strings.Builder
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				rows.Close()
				cancel()
				t.Fatal(err)
			}
			fmt.Fprintln(&plan, line)
		}
		rows.Close()
		err = rows.Err()
		if transactional {
			if _, rollbackErr := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT profile_trial"); rollbackErr != nil {
				cancel()
				t.Fatal(rollbackErr)
			}
			if _, releaseErr := tx.Exec(ctx, "RELEASE SAVEPOINT profile_trial"); releaseErr != nil {
				cancel()
				t.Fatal(releaseErr)
			}
		}
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("query=%s trial=%d\n%s", strings.SplitN(p.sql, "\n", 2)[0], trial+1, plan.String())
	}
}

func TestProfileRoutingRetention(t *testing.T) {
	f := newControlLoadFixture(t)
	if f.delay != 0 {
		t.Fatal("query profiles require DELAY=0ms")
	}
	sessions := readySteadyLoadSessions(t, f)
	var total int64
	var firstReceived, lastReceived time.Time
	if err := f.database.pool.QueryRow(t.Context(), `SELECT count(*),min(received_at),max(received_at) FROM control.service_audit_events`).Scan(&total, &firstReceived, &lastReceived); err != nil || total == 0 {
		t.Fatal("profile requires real service audit events", err)
	}
	tx, err := f.database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	p := &loadQueryPlan{DBTX: tx}
	queries := controlstatedb.New(p)
	empty, err := queries.CleanupServiceAuditEvents(t.Context(), controlstatedb.CleanupServiceAuditEventsParams{
		BeforeTime: timestamptz(firstReceived), BatchSize: 1000})
	if err != nil || empty != 0 {
		t.Fatalf("live service audit rows were deleted: %d: %v", empty, err)
	}
	t.Log("retention_profile current service audit rows must remain intact")
	p.explain(t)
	if _, err := tx.Exec(t.Context(), "SAVEPOINT profile_cleanup"); err != nil {
		t.Fatal(err)
	}
	batch, err := queries.CleanupServiceAuditEvents(t.Context(), controlstatedb.CleanupServiceAuditEventsParams{
		BeforeTime: timestamptz(lastReceived.Add(time.Microsecond)), BatchSize: 1000})
	if err != nil || batch != min(total, 1000) {
		t.Fatalf("profile cleanup batch=%d want=%d: %v", batch, min(total, 1000), err)
	}
	if _, err := tx.Exec(t.Context(), "ROLLBACK TO SAVEPOINT profile_cleanup"); err != nil {
		t.Fatal(err)
	}
	t.Logf("retention_profile services=%d actual_audit_events=%d first_batch=%d; all profile writes roll back", len(sessions), total, batch)
	p.explain(t)
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	var remaining int64
	if err := f.database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_audit_events`).Scan(&remaining); err != nil || remaining != total {
		t.Fatalf("profile did not roll back: %d %v", remaining, err)
	}
}
