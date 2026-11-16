package daemon

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func standaloneTestDatabase(t *testing.T) (string, *sql.DB) {
	t.Helper()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "standalone")
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err := controlstate.Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	return databaseURL, inspectStandaloneTestDatabase(t, databaseURL)
}

func inspectStandaloneTestDatabase(t *testing.T, databaseURL string) *sql.DB {
	t.Helper()
	config, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	inspect := stdlib.OpenDB(*config)
	t.Cleanup(func() { _ = inspect.Close() })
	return inspect
}

func waitForIngressRoutingCurrent(t *testing.T, database *sql.DB, expected int) {
	t.Helper()
	waitForIngressRoutingCurrentWithin(t, database, expected, 10*time.Second)
}

func waitForIngressRoutingCurrentWithin(t *testing.T, database *sql.DB, expected int, timeout time.Duration) {
	t.Helper()
	// this checks process leases only; service readiness also needs an applied
	// routing snapshot after the relevant control state has committed.
	waitForIntegrationCondition(t, timeout, func(ctx context.Context) (bool, error) {
		var current int
		err := database.QueryRowContext(ctx, `
			SELECT count(*) FROM control.ingress_leases
			WHERE NOT draining AND lease_expires_at > now()
		`).Scan(&current)
		return err == nil && current == expected, err
	})
}

func waitForAppliedServiceRouting(t *testing.T, database *sql.DB, runID string, metricsAddresses ...string) {
	t.Helper()
	var ready time.Time
	if err := database.QueryRowContext(integrationOperationContext(t), `SELECT ready_at FROM control.service_runs WHERE id=$1 AND state='ready'`, runID).Scan(&ready); err != nil {
		t.Fatal(err)
	}
	waitForIngressServiceRoutingAfter(t, ready, metricsAddresses, 10*time.Second)
}

func waitForIngressServiceRoutingAfter(t *testing.T, at time.Time, metricsAddresses []string, timeout time.Duration) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	waitForIntegrationCondition(t, timeout, func(ctx context.Context) (bool, error) {
		for _, address := range metricsAddresses {
			response, err := integrationGET(ctx, client, "http://"+address+"/metrics")
			if err != nil {
				return false, err
			}
			families, parseErr := observability.ParseMetrics(response.Body)
			if err := errors.Join(parseErr, response.Body.Close()); err != nil {
				return false, err
			}
			if response.StatusCode != http.StatusOK {
				return false, fmt.Errorf("ingress routing metrics status %d", response.StatusCode)
			}
			current := false
			for _, family := range families {
				if family.GetName() == "tnl_ingress_service_routing_observed_timestamp_seconds" && len(family.Metric) == 1 {
					observed := family.Metric[0].GetGauge().GetValue()
					required := float64(at.Unix()) + float64(at.Nanosecond())/float64(time.Second)
					current = observed >= required
				}
			}
			if !current {
				return false, nil
			}
		}
		return true, nil
	})
}

func waitForReadyPublisherConnections(t *testing.T, database *sql.DB, serviceID string, runNumber int64, expected int) {
	t.Helper()
	waitForIntegrationCondition(t, 25*time.Second, func(ctx context.Context) (bool, error) {
		var ready int
		err := database.QueryRowContext(ctx, `
			SELECT count(*) FROM control.service_connection_slots AS connections
			JOIN control.relay_leases AS leases
			  ON leases.relay_id = connections.relay_id
			 AND leases.relay_run_id = connections.relay_run_id
			 AND leases.relay_lease_revision = connections.relay_lease_revision
			WHERE connections.service_id = $1 AND connections.run_number = $2
			  AND connections.state = 'ready' AND NOT leases.draining AND leases.lease_expires_at > now()
		`, serviceID, runNumber).Scan(&ready)
		return err == nil && ready == expected, err
	})
}

func integrationPublisherDiagnostics(database *sql.DB, pebbleLogPath string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var order string
	queryErr := database.QueryRowContext(ctx, `
		SELECT jsonb_build_object(
			'id', orders.id, 'state', orders.state, 'order_revision', orders.order_revision,
			'service_id', orders.service_id, 'service_run_id', orders.service_run_id, 'run_number', orders.service_run_number,
			'work_owner', orders.work_owner, 'work_epoch', orders.work_epoch,
			'work_expires_at', orders.work_expires_at, 'available_at', orders.available_at,
			'last_error', orders.last_error,
			'authorizations', COALESCE((
				SELECT jsonb_agg(jsonb_build_object(
					'id', id, 'state', state, 'authorization_revision', authorization_revision,
					'available_at', available_at, 'presented_at', presented_at, 'expires_at', expires_at
				) ORDER BY identifier)
				FROM control.acme_authorizations WHERE order_id = orders.id
			), '[]'::jsonb)
		)::text
		FROM control.acme_orders AS orders ORDER BY created_at DESC, id LIMIT 1
	`).Scan(&order)
	var relayOrders string
	relayQueryErr := database.QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(jsonb_build_object(
		'id', id, 'state', state, 'hostname', tls_server_name, 'available_at', available_at,
		'work_expires_at', work_expires_at, 'last_error', last_error) ORDER BY id)::text, '[]')
		FROM control.relay_certificate_orders`).Scan(&relayOrders)
	pebbleLog, _ := os.ReadFile(pebbleLogPath)
	return fmt.Sprintf("; latest certificate order = %s, query error = %v; relay certificate orders = %s, query error = %v\n%s", order, queryErr, relayOrders, relayQueryErr, pebbleLog)
}

type splitConnectionState struct {
	publisherConnectionID string
	assignmentRevision    int64
	connectedRelayRunID   string
}

func readSplitConnectionState(t *testing.T, database *sql.DB, serviceID string, runNumber int64, relayServiceID string) splitConnectionState {
	t.Helper()
	var state splitConnectionState
	if err := database.QueryRowContext(integrationOperationContext(t), `
		SELECT publisher_connection_id, connection_assignment_revision, relay_run_id
		FROM control.service_connection_slots
		WHERE service_id = $1 AND run_number = $2 AND relay_service_id = $3 AND state = 'ready'
	`, serviceID, runNumber, relayServiceID).Scan(&state.publisherConnectionID, &state.assignmentRevision, &state.connectedRelayRunID); err != nil {
		t.Fatal(err)
	}
	return state
}

type splitProcessLease struct {
	runID     string
	revision  int64
	expiresAt time.Time
	err       error
}

func readSplitRelayLease(t *testing.T, database *sql.DB, relayID string) splitProcessLease {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	lease := readSplitRelayLeaseResult(ctx, database, relayID)
	if lease.err != nil {
		t.Fatal(lease.err)
	}
	return lease
}

func readSplitRelayLeaseResult(ctx context.Context, database *sql.DB, relayID string) splitProcessLease {
	var lease splitProcessLease
	lease.err = database.QueryRowContext(ctx, `SELECT relay_run_id, relay_lease_revision, lease_expires_at
		FROM control.relay_leases WHERE relay_id = $1`, relayID).Scan(&lease.runID, &lease.revision, &lease.expiresAt)
	return lease
}

func readSplitIngressLease(t *testing.T, database *sql.DB, ingressID string) splitProcessLease {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	lease := readSplitIngressLeaseResult(ctx, database, ingressID)
	if lease.err != nil {
		t.Fatal(lease.err)
	}
	return lease
}

func readSplitIngressLeaseResult(ctx context.Context, database *sql.DB, ingressID string) splitProcessLease {
	var lease splitProcessLease
	lease.err = database.QueryRowContext(ctx, `SELECT ingress_run_id, ingress_lease_revision, lease_expires_at
		FROM control.ingress_leases WHERE ingress_id = $1`, ingressID).Scan(&lease.runID, &lease.revision, &lease.expiresAt)
	return lease
}

func assertSplitRoutePlacement(t *testing.T, database *sql.DB, serviceID string, runNumber int64) {
	t.Helper()
	var connections, services, relays int
	if err := database.QueryRowContext(integrationOperationContext(t), `
		SELECT count(*), count(DISTINCT relay_service_id), count(DISTINCT relay_id)
		FROM control.service_connection_slots WHERE service_id = $1 AND run_number = $2 AND state = 'ready'
	`, serviceID, runNumber).Scan(&connections, &services, &relays); err != nil {
		t.Fatal(err)
	}
	if connections != 2 || services != 2 || relays != 2 {
		t.Fatalf("split route placement = %d connections across %d services and %d relays", connections, services, relays)
	}
}

func assertServiceRunNumber(t *testing.T, database *sql.DB, serviceID string, runNumber int64) {
	t.Helper()
	var current int64
	if err := database.QueryRowContext(integrationOperationContext(t), `SELECT run_number
		FROM control.service_runs WHERE service_id = $1 AND closed_at IS NULL`, serviceID).Scan(&current); err != nil {
		t.Fatal(err)
	}
	if current != runNumber {
		t.Fatalf("service run number = %d, want %d", current, runNumber)
	}
}

func integrationServiceOrderCount(t *testing.T, database *sql.DB, serviceID string) int {
	t.Helper()
	var count int
	if err := database.QueryRowContext(integrationOperationContext(t), `SELECT count(*) FROM control.acme_orders WHERE service_id = $1`, serviceID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func assertSplitLeases(t *testing.T, database *sql.DB, activeIngress, activeRelays, drainingIngress, drainingRelays int) {
	t.Helper()
	var gotActiveIngress, gotActiveRelays, gotDrainingIngress, gotDrainingRelays int
	if err := database.QueryRowContext(integrationOperationContext(t), `SELECT
		(SELECT count(*) FROM control.ingress_leases WHERE NOT draining AND lease_expires_at > now()),
		(SELECT count(*) FROM control.relay_leases WHERE NOT draining AND lease_expires_at > now()),
		(SELECT count(*) FROM control.ingress_leases WHERE draining),
		(SELECT count(*) FROM control.relay_leases WHERE draining)
	`).Scan(&gotActiveIngress, &gotActiveRelays, &gotDrainingIngress, &gotDrainingRelays); err != nil {
		t.Fatal(err)
	}
	if gotActiveIngress != activeIngress || gotActiveRelays != activeRelays || gotDrainingIngress != drainingIngress || gotDrainingRelays != drainingRelays {
		t.Fatalf("split leases = active ingress/relays %d/%d, draining ingress/relays %d/%d", gotActiveIngress, gotActiveRelays, gotDrainingIngress, gotDrainingRelays)
	}
}
