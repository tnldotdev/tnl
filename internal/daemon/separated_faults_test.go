package daemon

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
)

func runtimeBlackhole(scenario string) bool {
	return scenario == "forwarding-blackhole" || scenario == "publisher-blackhole"
}

func runtimeEarlyFault(scenario string) bool {
	return scenario == "udp-fallback" || scenario == "latency" || scenario == "packet-loss"
}

func runtimeControlledFault(scenario string) bool {
	return runtimeBlackhole(scenario) || runtimeEarlyFault(scenario)
}

func separatedProbe(t *testing.T, sequence *int, phase benchworkload.Phase) {
	t.Helper()
	separatedWrite(t, fmt.Sprintf("phase-%d", *sequence), phase)
	*sequence = *sequence + 1
	var results []separatedVisitorResult
	held := 0
	visitors := separatedNames("visitors")
	sources := len(visitors)
	timeout := time.Duration((len(phase.URLs)+sources-1)/sources+2)*5*time.Second + time.Second
	heldTotal := phase.HeldStreams
	if phase.OpenHeld {
		heldTotal = min(8, len(phase.URLs))
	}
	heldTimeout := time.Duration(benchworkload.Assignment(heldTotal, sources, 0))*time.Second/500 + 10*time.Second
	timeout = max(timeout, heldTimeout+time.Duration(benchworkload.Assignment(heldTotal, sources, 0))*100*time.Millisecond)
	for _, visitor := range visitors {
		var result separatedVisitorResult
		separatedWait(t, phase.Name+"."+visitor, timeout, &result)
		results = append(results, result)
		held += result.HeldSurviving
		for _, row := range result.Requests {
			if row.Error != "" {
				t.Errorf("%s: %s", phase.Name, row.Error)
			}
		}
		if phase.OpenHeld && result.HealthyHeld == 0 {
			t.Errorf("%s: %s opened no healthy held stream", phase.Name, visitor)
		}
	}
	if phase.HeldStreams > 0 && held != phase.HeldStreams {
		t.Errorf("%s opened %d held streams, want %d", phase.Name, held, phase.HeldStreams)
	}
	separatedResult(t, phase.Name+"-visitors", results)
	if phase.HeldStreams > 0 {
		separatedReportHeld(t, phase.Name, results, phase.HeldStreams, true, false, false)
	}
	if phase.Name == "direct-held-close" {
		separatedReportHeld(t, phase.Name, results, *runtimeLoadHeldStreams, false, false, true)
	}
	if phase.Name == "tunnel-held-close" {
		separatedReportHeld(t, phase.Name, results, *runtimeLoadHeldStreams, false, false, true)
	}
}

func separatedWaitForRecovery(t *testing.T, database *sql.DB, publishers separatedPublishers, timeout time.Duration) time.Time {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	if err := separatedAwaitServiceConnections(ctx, database, publishers.Runs); err != nil {
		t.Fatalf("publisher connections did not recover within %s: %v; current assignments=%s", timeout, err, separatedConnectionAssignments(t, database))
	}
	waitForSeparatedServiceRouting(t, database, separatedRoutingAcknowledgmentTimeout)
	for _, ready := range publishers.Runs {
		var id string
		var number int64
		if err := database.QueryRowContext(integrationOperationContext(t), `SELECT id,run_number FROM control.service_runs WHERE service_id=$1 ORDER BY run_number DESC LIMIT 1`, ready.ServiceID).Scan(&id, &number); err != nil ||
			id != ready.RunID || number != ready.Number {
			t.Fatal("recovery replaced the service run instead of repairing its connections", err)
		}
	}
	return time.Now()
}

func waitForSeparatedServiceRouting(t *testing.T, database *sql.DB, timeout time.Duration) {
	t.Helper()
	// capture database time after the expected connections or closures are
	// visible. the original run ready_at does not prove replacement routing.
	var committed time.Time
	if err := database.QueryRowContext(integrationOperationContext(t), `SELECT clock_timestamp()`).Scan(&committed); err != nil {
		t.Fatal(err)
	}
	var addresses []string
	for _, ingress := range separatedNames("ingresses") {
		addresses = append(addresses, ingress+":9090")
	}
	waitForIngressServiceRoutingAfter(t, committed, addresses, timeout)
}

func separatedAwaitServiceConnections(ctx context.Context, database *sql.DB, expected []benchworkload.ServiceRun) error {
	services, runs, numbers := make([]string, len(expected)), make([]string, len(expected)), make([]int64, len(expected))
	for index, run := range expected {
		if !run.Valid() {
			return fmt.Errorf("publisher %d has no exact service run", index)
		}
		services[index], runs[index], numbers[index] = run.ServiceID, run.RunID, run.Number
	}
	return pollCondition(ctx, 25*time.Millisecond, 2*time.Second, func(ctx context.Context) (bool, error) {
		var count int
		err := database.QueryRowContext(ctx, `SELECT count(*) FROM control.service_connection_slots c
			JOIN unnest($1::text[],$2::text[],$3::bigint[]) expected(service_id,run_id,run_number)
				ON (c.service_id,c.service_run_id,c.run_number)=(expected.service_id,expected.run_id,expected.run_number)
			JOIN control.service_runs run ON (run.id,run.service_id,run.run_number)=(c.service_run_id,c.service_id,c.run_number)
			JOIN control.relay_leases l ON l.relay_id = c.relay_id AND l.relay_run_id = c.relay_run_id
			AND l.relay_lease_revision = c.relay_lease_revision
			WHERE c.session_open AND c.state = 'ready' AND run.state='ready'
				AND run.closed_at IS NULL AND run.publisher_expires_at>now()
				AND NOT l.draining AND l.lease_expires_at > now()`, services, runs, numbers).Scan(&count)
		return count == len(expected)*2, err
	})
}

func separatedConnectionAssignments(t *testing.T, database *sql.DB) string {
	t.Helper()
	var assignments string
	if err := database.QueryRowContext(integrationOperationContext(t), `
		SELECT coalesce(jsonb_agg(jsonb_build_array(service_id, service_run_id, run_number, connection_slot,
			publisher_connection_id, connection_assignment_revision, relay_service_id,
			relay_id, relay_run_id, relay_lease_revision, state)
			ORDER BY service_id, connection_slot), '[]'::jsonb)::text
		FROM control.service_connection_slots WHERE session_open AND state IN ('assigned', 'connected', 'ready')
	`).Scan(&assignments); err != nil {
		t.Fatal(err)
	}
	return assignments
}
