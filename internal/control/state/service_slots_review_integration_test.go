package state

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationServiceSlotsHaveOneRunParent(t *testing.T) {
	f, _ := guestAuthorityFixture(t, true)
	var ready int
	err := f.database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_connection_slots
		WHERE service_run_id=$1 AND service_id=$2 AND run_number=$3 AND state='ready' AND session_open`,
		f.run.RunID, f.service.ID, f.run.RunNumber).Scan(&ready)
	if err != nil || ready != 2 {
		t.Fatalf("ready service slots: count=%d error=%v", ready, err)
	}
	counts, err := controlstatedb.New(f.database.pool).CountOpenServiceRunAssignmentsByRelayService(t.Context())
	if err != nil || len(counts) != 2 || counts[0].AssignmentCount != 1 || counts[1].AssignmentCount != 1 {
		t.Fatalf("two relay reservations for the run: %+v %v", counts, err)
	}
	var oldTables int
	err = f.database.pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_class
		WHERE oid=ANY(ARRAY[
			to_regclass('control.publisher_service_connection_slots'),
			to_regclass('control.publish_run_connection_slots'),
			to_regclass('control.publisher_service_runs')])`).Scan(&oldTables)
	if err != nil || oldTables != 0 {
		t.Fatalf("old slot or run views remain: count=%d error=%v", oldTables, err)
	}
	// an assignment cannot be moved to a different saved service or run.
	_, err = f.database.pool.Exec(t.Context(), `UPDATE control.service_connection_slots
		SET service_id='svc_wrong' WHERE publisher_connection_id=$1`, f.run.Connections[0].PublisherConnectionID)
	var violation *pgconn.PgError
	if !errors.As(err, &violation) || violation.Code != "23503" {
		t.Fatalf("slot escaped its run parent: %v", err)
	}
	if err := f.database.CloseServiceRun(f.ctx, f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	err = f.database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_connection_slots
		WHERE service_run_id=$1 AND session_open`, f.run.RunID).Scan(&ready)
	if err != nil || ready != 0 {
		t.Fatalf("closed run kept active slots: count=%d error=%v", ready, err)
	}
}
