package controlstate

import (
	"testing"
	"time"
)

// Seed before starting workload actors. The first f.routes events are genuine
// ready-route projections, one per route. Copy them to grow retained history
// without changing current connections or simulating elapsed lease time.
func seedLoadRoutingHistory(t *testing.T, f *controlLoadFixture, previous, perRoute int) int64 {
	t.Helper()
	if previous < 1 || perRoute < previous {
		t.Fatal("routing history must grow from at least one event per route")
	}
	started := time.Now()
	if perRoute > previous {
		_, err := f.database.pool.Exec(t.Context(), `
			INSERT INTO control.ingress_routing_table_events
				(event_kind, route_id, route_version, canonical_hostname, entry_revision,
				 projection, route_expires_at, created_at)
			SELECT seed.event_kind, seed.route_id, seed.route_version, seed.canonical_hostname,
				seed.entry_revision + sweep - 1, seed.projection, seed.route_expires_at, seed.created_at
			FROM control.ingress_routing_table_events AS seed
			CROSS JOIN generate_series($1::integer, $2::integer) AS sweep
			WHERE seed.routing_table_revision <= $3::bigint
			ORDER BY sweep, seed.routing_table_revision`, previous+1, perRoute, f.routes)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.database.pool.Exec(t.Context(), `
		UPDATE control.ingress_routing_table_clock
		SET current_revision = (SELECT max(routing_table_revision) FROM control.ingress_routing_table_events);
		ANALYZE control.ingress_routing_table_events`); err != nil {
		t.Fatal(err)
	}
	var total, revision, bytes int64
	if err := f.database.pool.QueryRow(t.Context(), `SELECT count(*), max(routing_table_revision),
		pg_total_relation_size('control.ingress_routing_table_events')
		FROM control.ingress_routing_table_events`).Scan(&total, &revision, &bytes); err != nil {
		t.Fatal(err)
	}
	if total != int64(f.routes)*int64(perRoute) || revision != total {
		t.Fatalf("history rows=%d revision=%d want=%d", total, revision, int64(f.routes)*int64(perRoute))
	}
	t.Logf("routes=%d history_events=%d events_per_route=%d relation_bytes=%d history_setup_elapsed=%s (no injected SQL delay)",
		f.routes, total, perRoute, bytes, time.Since(started))
	return total
}
