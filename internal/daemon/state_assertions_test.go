package daemon

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
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
	// wait for the state that preceded this barrier. ongoing publisher heartbeats
	// must not move its goal past an ingress's otherwise sufficient acknowledgment.
	var revision int64
	if err := database.QueryRowContext(integrationOperationContext(t), `SELECT current_revision FROM control.ingress_routing_table_clock`).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	waitForIntegrationCondition(t, timeout, func(ctx context.Context) (bool, error) {
		var current, applied int
		err := database.QueryRowContext(ctx, `
			SELECT count(*), count(*) FILTER (WHERE leases.routing_table_revision >= $1)
			FROM control.ingress_leases AS leases
			WHERE NOT leases.draining AND leases.lease_expires_at > now()
		`, revision).Scan(&current, &applied)
		return err == nil && current == expected && applied == expected, err
	})
}

func waitForReadyPublisherConnections(t *testing.T, database *sql.DB, publicURLID string, publishRunNumber uint64, expected int) {
	t.Helper()
	waitForIntegrationCondition(t, 25*time.Second, func(ctx context.Context) (bool, error) {
		var ready int
		err := database.QueryRowContext(ctx, `
			SELECT count(*) FROM control.publish_run_connection_slots AS connections
			JOIN control.relay_leases AS leases
			  ON leases.relay_id = connections.connected_relay_id
			 AND leases.relay_run_id = connections.connected_relay_run_id
			 AND leases.relay_lease_revision = connections.connected_relay_lease_revision
			WHERE connections.public_url_id = $1 AND connections.publish_run_number = $2
			  AND connections.state = 'ready' AND NOT leases.draining AND leases.lease_expires_at > now()
		`, publicURLID, publishRunNumber).Scan(&ready)
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
	var serving string
	servingErr := database.QueryRowContext(ctx, `SELECT jsonb_build_object(
		'observed_at',clock_timestamp(),
		'runs',(SELECT jsonb_agg(facts) FROM (SELECT id,public_url_id,publish_run_number,state,publisher_expires_at,ready_at,certificate_installed_at,certificate_not_after FROM control.publish_runs ORDER BY created_at DESC LIMIT 16) facts),
		'slots',(SELECT jsonb_agg(facts) FROM (SELECT publish_run_id,publisher_connection_id,state,session_open,connected_relay_id,connected_relay_run_id,connected_relay_lease_revision FROM control.publish_run_connection_slots ORDER BY publisher_connection_id LIMIT 32) facts),
		'allocations',(SELECT jsonb_agg(facts) FROM (SELECT id,resource_id,run_id,run_number,ingress_id,ingress_run_id,ingress_lease_revision,valid_until,publisher_observed_until,ingress_observed_until,retired_at FROM control.stream_capacity_allocations ORDER BY id LIMIT 32) facts),
		'ingresses',(SELECT jsonb_agg(facts) FROM (SELECT ingress_id,ingress_run_id,ingress_lease_revision,ingress_pool_id,connector_only,draining,protocol_version,connection_capacity,routing_table_revision,lease_expires_at FROM control.ingress_leases ORDER BY ingress_id LIMIT 16) facts),
		'relays',(SELECT jsonb_agg(facts) FROM (SELECT relay_id,relay_run_id,relay_lease_revision,draining,lease_expires_at FROM control.relay_leases ORDER BY relay_id LIMIT 16) facts),
		'routing_revision',(SELECT max(id) FROM control.ingress_routing_table_events)
	)::text`).Scan(&serving)
	pebbleLog, _ := os.ReadFile(pebbleLogPath)
	return fmt.Sprintf("; latest certificate order = %s, query error = %v; serving preparation = %s, query error = %v\n%s", order, queryErr, serving, servingErr, pebbleLog)
}

type splitConnectionState struct {
	publisherConnectionID string
	assignmentRevision    int64
	connectedRelayRunID   string
}

func readSplitConnectionState(t *testing.T, database *sql.DB, publicURLID string, publishRunNumber uint64, relayServiceID string) splitConnectionState {
	t.Helper()
	var state splitConnectionState
	if err := database.QueryRowContext(integrationOperationContext(t), `
		SELECT publisher_connection_id, connection_assignment_revision, connected_relay_run_id
		FROM control.publish_run_connection_slots
		WHERE public_url_id = $1 AND publish_run_number = $2 AND relay_service_id = $3 AND state = 'ready'
	`, publicURLID, publishRunNumber, relayServiceID).Scan(&state.publisherConnectionID, &state.assignmentRevision, &state.connectedRelayRunID); err != nil {
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

func assertSplitRoutePlacement(t *testing.T, database *sql.DB, publicURLID string, publishRunNumber uint64) {
	t.Helper()
	var connections, services, relays int
	if err := database.QueryRowContext(integrationOperationContext(t), `
		SELECT count(*), count(DISTINCT relay_service_id), count(DISTINCT connected_relay_id)
		FROM control.publish_run_connection_slots WHERE public_url_id = $1 AND publish_run_number = $2 AND state = 'ready'
	`, publicURLID, publishRunNumber).Scan(&connections, &services, &relays); err != nil {
		t.Fatal(err)
	}
	if connections != 2 || services != 2 || relays != 2 {
		t.Fatalf("split route placement = %d connections across %d services and %d relays", connections, services, relays)
	}
}

func assertPublishRunNumber(t *testing.T, database *sql.DB, publicURLID string, publishRunNumber uint64) {
	t.Helper()
	var current int64
	if err := database.QueryRowContext(integrationOperationContext(t), `SELECT publish_run_number
		FROM control.publish_runs WHERE public_url_id = $1 AND closed_at IS NULL`, publicURLID).Scan(&current); err != nil {
		t.Fatal(err)
	}
	if uint64(current) != publishRunNumber {
		t.Fatalf("publish run number = %d, want %d", current, publishRunNumber)
	}
}

func integrationRouteOrderCount(t *testing.T, database *sql.DB, publicURLID string) int {
	t.Helper()
	var count int
	if err := database.QueryRowContext(integrationOperationContext(t), `SELECT count(*) FROM control.acme_orders WHERE public_url_id = $1`, publicURLID).Scan(&count); err != nil {
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
