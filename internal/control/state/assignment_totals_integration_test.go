package state

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func assertAssignmentTotals(t *testing.T, db controlstatedb.DBTX, want int64) {
	t.Helper()
	var mismatches, total int64
	err := db.QueryRow(t.Context(), `
		WITH actual AS (
			SELECT connections.relay_service_id, count(*) AS assignment_count
			FROM control.service_connection_slots AS connections
			JOIN control.service_runs AS sessions ON sessions.id = connections.service_run_id
			WHERE sessions.closed_at IS NULL
			  AND connections.state IN ('assigned', 'connected', 'ready')
			GROUP BY connections.relay_service_id
		)
		SELECT count(*) FILTER (WHERE totals.reserved_slot_count IS DISTINCT FROM COALESCE(actual.assignment_count, 0)),
		       COALESCE(sum(totals.reserved_slot_count), 0)::bigint
		FROM control.relay_services AS services
		LEFT JOIN control.relay_service_reservations AS totals USING (relay_service_id)
		LEFT JOIN actual USING (relay_service_id)
	`).Scan(&mismatches, &total)
	if err != nil || mismatches != 0 || total != want {
		t.Fatalf("assignment totals: mismatches=%d total=%d, want 0/%d: %v", mismatches, total, want, err)
	}
}
