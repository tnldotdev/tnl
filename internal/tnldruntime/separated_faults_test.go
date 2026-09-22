package tnldruntime

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	for i := 1; i <= 4; i++ {
		var result separatedVisitorResult
		separatedWait(t, fmt.Sprintf("%s.visitor-%d", phase.Name, i), time.Duration((len(phase.URLs)+3)/4+2)*5*time.Second+time.Second, &result)
		results = append(results, result)
		for _, row := range result.Requests {
			if row.Error != "" {
				t.Errorf("%s: %s", phase.Name, row.Error)
			}
		}
		if phase.OpenHeld && result.HealthyHeld == 0 {
			t.Errorf("%s: visitor-%d opened no healthy held stream", phase.Name, i)
		}
	}
	data, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("/results", phase.Name+"-visitors.json"), data, 0o644); err != nil {
		t.Fatal(err)
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
	waitForIngressRoutingCurrent(t, database, 1)
	for _, ready := range publishers.Ready {
		assertRouteVersion(t, database, ready.RouteID, ready.RouteVersion)
	}
	return time.Now()
}
