package controlstate

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
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
		if _, err := f.database.CreatePublishRun(t.Context(), f.request(index), f.now, time.Hour, time.Hour); err != nil {
			t.Fatal(err)
		}
		count := index + 1
		if count != 1000 && count != 2500 && count != f.routes {
			continue
		}
		if _, err := f.database.pool.Exec(t.Context(), "ANALYZE control.publish_runs; ANALYZE control.publish_run_connections"); err != nil {
			t.Fatal(err)
		}
		rows, err := queries.CountOpenPublishRunAssignmentsByRelayService(t.Context())
		if err != nil || len(rows) != 2 {
			t.Fatalf("assignment counts: services=%d: %v", len(rows), err)
		}
		for _, row := range rows {
			if row.AssignmentCount != int64(count) {
				t.Fatalf("service=%s assignments=%d want=%d", row.RelayServiceID, row.AssignmentCount, count)
			}
		}
		t.Logf("routes=%d assignments=%d", count, 2*count)
		p.explain(t)
	}
}

func TestProfileRoutingHistory(t *testing.T) {
	f := newControlLoadFixture(t)
	if f.delay != 0 {
		t.Fatal("query profiles require DELAY=0ms")
	}
	readySteadyLoadSessions(t, f)
	ingress, err := f.database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "profile-ingress", IngressRunID: "profile-run", ProtocolVersion: 1,
		ConnectionCapacity: uint64(f.routes),
	}, f.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// measure read amplification with a fixed set of routable public URLs.
	// no concurrent writers run during these profiles.
	p := &loadQueryPlan{DBTX: f.database.pool}
	queries := controlstatedb.New(p)
	previous := 1
	for _, perPublicURL := range []int{4, 10, 100} {
		total := seedLoadRoutingHistory(t, f, previous, perPublicURL)
		// snapshot timing comes from the same production histograms as load runs.
		// scope the defer to this stage so failures retain its completed samples.
		func() {
			f.startMetrics(t)
			defer f.logStats(t)
			for trial := range 3 {
				ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
				snapshot, err := f.controls[trial%2].ReadIngressRoutingTableSnapshot(ctx, ingress.IngressLeaseIdentity, f.now)
				cancel()
				t.Logf("history_events=%d snapshot_trial=%d", total, trial+1)
				if err != nil || len(snapshot.Entries) != f.routes || snapshot.RoutingTableRevision != uint64(total) {
					t.Fatalf("snapshot routes=%d revision=%d: %v", len(snapshot.Entries), snapshot.RoutingTableRevision, err)
				}
				seen := make(map[string]bool, f.routes)
				for _, event := range snapshot.Entries {
					if seen[event.PublicURLID] || event.EntryRevision != uint64(perPublicURL) || len(event.Projection.PublisherConnections) != 2 {
						t.Fatalf("unexpected snapshot route=%s entry=%d", event.PublicURLID, event.EntryRevision)
					}
					seen[event.PublicURLID] = true
				}
			}
		}()
		if _, err := queries.ListIngressRoutingTableSnapshot(t.Context(), controlstatedb.ListIngressRoutingTableSnapshotParams{
			Now: timestamptz(f.now), ThroughRevision: total,
		}); err != nil {
			t.Fatal(err)
		}
		p.explain(t)
		pageSize := min(total, int64(MaximumIngressRoutingTablePageSize))
		rows, err := queries.ListIngressRoutingTableEvents(t.Context(), controlstatedb.ListIngressRoutingTableEventsParams{
			AfterRevision: total - pageSize, ThroughRevision: total, PageLimit: int32(pageSize),
		})
		if err != nil || len(rows) != int(pageSize) {
			t.Fatalf("delta rows=%d want=%d: %v", len(rows), pageSize, err)
		}
		for index, row := range rows {
			if row.RoutingTableRevision != total-pageSize+int64(index)+1 {
				t.Fatal("unordered delta page")
			}
		}
		p.explain(t)
		previous = perPublicURL
	}
}

// record the actual sqlc query and its parameters instead of maintaining a
// second copy of production SQL in a profiling fixture. calls are serial.
type loadQueryPlan struct {
	controlstatedb.DBTX
	sql  string
	args []any
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
	readySteadyLoadSessions(t, f)
	total := seedLoadRoutingHistory(t, f, 1, f.history)
	tx, err := f.database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	queries := controlstatedb.New(tx)
	p := &loadQueryPlan{DBTX: tx}
	empty, err := controlstatedb.New(p).PruneIngressRoutingHistoryBatch(t.Context(), 0)
	if err != nil || empty.Scanned != 0 {
		t.Fatalf("zero-floor batch=%+v: %v", empty, err)
	}
	t.Log("retention_profile zero floor must stop at the revision index boundary")
	p.explain(t)
	if _, err := queries.AdvanceIngressRoutingRetentionFloor(t.Context(), total); err != nil {
		t.Fatal(err)
	}
	if _, err := queries.TryLockIngressRoutingHistoryCleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	batch, err := controlstatedb.New(p).PruneIngressRoutingHistoryBatch(t.Context(), 0)
	if err != nil || batch.Scanned > 1000 || batch.Deleted == 0 {
		t.Fatalf("profile batch=%+v: %v", batch, err)
	}
	t.Logf("retention_profile routes=%d initial_events=%d first_batch=%+v; all profile writes roll back", f.routes, total, batch)
	p.explain(t)
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	var remaining int64
	if err := f.database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.ingress_routing_table_events`).Scan(&remaining); err != nil || remaining != total {
		t.Fatalf("profile did not roll back: %d %v", remaining, err)
	}
}
