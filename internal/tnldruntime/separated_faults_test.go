package tnldruntime

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
	timeout := time.Duration((len(phase.URLs)+3)/4+2)*5*time.Second + time.Second
	heldTotal := phase.HeldStreams
	if phase.OpenHeld {
		heldTotal = min(8, len(phase.URLs))
	}
	heldTimeout := time.Duration(float64(benchworkload.Assignment(heldTotal, 4, 0))/runtimeLoadAdmission.SourceConnectionRate*float64(time.Second)) + 10*time.Second
	timeout = max(timeout, heldTimeout+time.Duration(benchworkload.Assignment(heldTotal, 4, 0))*100*time.Millisecond)
	for i := 1; i <= 4; i++ {
		var result separatedVisitorResult
		separatedWait(t, fmt.Sprintf("%s.visitor-%d", phase.Name, i), timeout, &result)
		results = append(results, result)
		held += result.HeldSurviving
		for _, row := range result.Requests {
			if row.Error != "" {
				t.Errorf("%s: %s", phase.Name, row.Error)
			}
		}
		if phase.OpenHeld && result.HealthyHeld == 0 {
			t.Errorf("%s: visitor-%d opened no healthy held stream", phase.Name, i)
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

func separatedWaitForRecovery(t *testing.T, database *sql.DB, publishers separatedPublishers) time.Time {
	t.Helper()
	waitForIntegrationCondition(t, 25*time.Second, func(ctx context.Context) (bool, error) {
		var count int
		err := database.QueryRowContext(ctx, `SELECT count(*) FROM control.route_session_connections c
			JOIN control.relay_leases l ON l.relay_id = c.connected_relay_id AND l.relay_run_id = c.connected_relay_run_id
			AND l.relay_lease_revision = c.connected_relay_lease_revision
			WHERE c.state = 'ready' AND NOT l.draining AND l.lease_expires_at > now()`).Scan(&count)
		return count == len(publishers.Ready)*2, err
	})
	waitForIngressRoutingCurrent(t, database, len(separatedIngresses()))
	for _, ready := range publishers.Ready {
		assertRouteVersion(t, database, ready.RouteID, ready.RouteVersion)
	}
	return time.Now()
}

func separatedConnectionAssignments(t *testing.T, database *sql.DB) string {
	t.Helper()
	var assignments string
	if err := database.QueryRowContext(integrationOperationContext(t), `
		SELECT coalesce(jsonb_agg(jsonb_build_array(route_id, route_version, connection_slot,
			publisher_connection_id, connection_assignment_revision, relay_service_id,
			connected_relay_id, connected_relay_run_id, connected_relay_lease_revision, state)
			ORDER BY route_id, connection_slot), '[]'::jsonb)::text
		FROM control.route_session_connections WHERE state IN ('assigned', 'connected', 'ready')
	`).Scan(&assignments); err != nil {
		t.Fatal(err)
	}
	return assignments
}
