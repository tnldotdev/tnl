package state

import (
	"testing"
	"time"
)

// seed before starting workload actors. each URL already has its genuine
// preparation and ready projections. copy only the final ready projection to
// grow history without changing connections or simulating elapsed lease time.
func seedLoadRoutingHistory(t *testing.T, f *controlLoadFixture, previous, perPublicURL int) int64 {
	t.Helper()
	if previous < 2 || perPublicURL < previous {
		t.Fatal("routing history must retain preparation and ready events")
	}
	started := time.Now()
	if perPublicURL > previous {
		_, err := f.database.pool.Exec(t.Context(), `
			WITH seeds AS (
				SELECT DISTINCT ON (public_url_id, publish_run_number) *
				FROM control.ingress_routing_table_events
				ORDER BY public_url_id, publish_run_number, id DESC
			)
			INSERT INTO control.ingress_routing_table_events
				(event_kind, public_url_id, publish_run_number, canonical_hostname, entry_revision,
				 projection, public_url_expires_at, created_at)
			SELECT seed.event_kind, seed.public_url_id, seed.publish_run_number, seed.canonical_hostname,
				sweep, seed.projection, seed.public_url_expires_at, seed.created_at
			FROM seeds AS seed
			CROSS JOIN generate_series($1::bigint, $2::bigint) AS sweep
			ORDER BY sweep, seed.id`, previous+1, perPublicURL)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.database.pool.Exec(t.Context(), `
		UPDATE control.ingress_routing_table_clock
		SET current_revision = (SELECT max(id) FROM control.ingress_routing_table_events);
		ANALYZE control.ingress_routing_table_events`); err != nil {
		t.Fatal(err)
	}
	var total, revision, bytes int64
	if err := f.database.pool.QueryRow(t.Context(), `SELECT count(*), max(id),
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
