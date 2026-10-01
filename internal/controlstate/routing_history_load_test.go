package controlstate

import (
	"testing"
	"time"
)

// seed before starting workload actors. the first f.routes events are genuine
// routable public URL projections, one per public URL. copy them to grow history
// without changing current connections or simulating elapsed lease time.
func seedLoadRoutingHistory(t *testing.T, f *controlLoadFixture, previous, perPublicURL int) int64 {
	t.Helper()
	if previous < 1 || perPublicURL < previous {
		t.Fatal("routing history must grow from at least one event per route")
	}
	started := time.Now()
	if perPublicURL > previous {
		_, err := f.database.pool.Exec(t.Context(), `
			INSERT INTO control.ingress_routing_table_events
				(event_kind, public_url_id, publish_run_number, canonical_hostname, entry_revision,
				 projection, public_url_expires_at, created_at)
			SELECT seed.event_kind, seed.public_url_id, seed.publish_run_number, seed.canonical_hostname,
				seed.entry_revision + sweep - 1, seed.projection, seed.public_url_expires_at, seed.created_at
			FROM control.ingress_routing_table_events AS seed
			CROSS JOIN generate_series($1::integer, $2::integer) AS sweep
			WHERE seed.routing_table_revision <= $3::bigint
			ORDER BY sweep, seed.routing_table_revision`, previous+1, perPublicURL, f.routes)
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
	if total != int64(f.routes)*int64(perPublicURL) || revision != total {
		t.Fatalf("history rows=%d revision=%d want=%d", total, revision, int64(f.routes)*int64(perPublicURL))
	}
	t.Logf("routes=%d history_events=%d events_per_route=%d relation_bytes=%d history_setup_elapsed=%s (no injected SQL delay)",
		f.routes, total, perPublicURL, bytes, time.Since(started))
	return total
}
