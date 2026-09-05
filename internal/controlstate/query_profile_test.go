package controlstate

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

// Profiles are explicitly selected with RUN=^TestProfile. They use the load
// fixture, but measure isolated SQL plans, not the concurrent load workload.
func TestProfilePlacementQueries(t *testing.T) {
	f := newControlLoadFixture(t)
	if f.delay != 0 {
		t.Fatal("query profiles require DELAY=0ms")
	}
	p := &loadQueryPlan{Pool: f.database.pool}
	queries := controlstatedb.New(p)
	for index := range f.routes {
		if _, err := f.database.CreateRouteSession(t.Context(), f.request(index), f.now, time.Hour, time.Hour); err != nil {
			t.Fatal(err)
		}
		count := index + 1
		if count != 1000 && count != 2500 && count != f.routes {
			continue
		}
		if _, err := f.database.pool.Exec(t.Context(), "ANALYZE control.route_sessions; ANALYZE control.route_session_connections"); err != nil {
			t.Fatal(err)
		}
		rows, err := queries.CountOpenRouteSessionAssignmentsByRelayService(t.Context())
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
	// Measure read amplification with a fixed set of genuine ready routes.
	// No concurrent writers run during these profiles.
	p := &loadQueryPlan{Pool: f.database.pool}
	queries := controlstatedb.New(p)
	previous := 1
	for _, perRoute := range []int{4, 10, 100} {
		total := seedLoadRoutingHistory(t, f, previous, perRoute)
		// Snapshot timing comes from the same production histograms as load runs.
		// Scope the defer to this stage so failures retain its completed samples.
		func() {
			f.startMetrics(t)
			defer f.logStats(t)
			for trial := range 3 {
				ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
				snapshot, err := f.controls[trial%2].ReadIngressRoutingTableSnapshot(ctx, ingress.IngressLeaseIdentity, f.now)
				cancel()
				t.Logf("history_events=%d snapshot_trial=%d", total, trial+1)
				if err != nil || len(snapshot.Routes) != f.routes || snapshot.RoutingTableRevision != uint64(total) {
					t.Fatalf("snapshot routes=%d revision=%d: %v", len(snapshot.Routes), snapshot.RoutingTableRevision, err)
				}
				seen := make(map[string]bool, f.routes)
				for _, event := range snapshot.Routes {
					if seen[event.RouteID] || event.EntryRevision != uint64(perRoute) || len(event.Projection.PublisherConnections) != 2 {
						t.Fatalf("unexpected snapshot route=%s entry=%d", event.RouteID, event.EntryRevision)
					}
					seen[event.RouteID] = true
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
		previous = perRoute
	}
}

// Record the actual sqlc query and its parameters instead of maintaining a
// second copy of production SQL in a profiling fixture. Calls are serial.
type loadQueryPlan struct {
	*pgxpool.Pool
	sql  string
	args []any
}

func (p *loadQueryPlan) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	p.sql, p.args = sql, args
	return p.Pool.Query(ctx, sql, args...)
}

func (p *loadQueryPlan) explain(t *testing.T) {
	t.Helper()
	for trial := range 3 {
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		rows, err := p.Pool.Query(ctx, "EXPLAIN (ANALYZE, BUFFERS, SETTINGS) "+p.sql, p.args...)
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
