package tnldruntime

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/tnldotdev/tnl/internal/controlstate"
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
			SELECT count(*) FROM control.publish_run_connections AS connections
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
	pebbleLog, _ := os.ReadFile(pebbleLogPath)
	return fmt.Sprintf("; latest certificate order = %s, query error = %v\n%s", order, queryErr, pebbleLog)
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
		FROM control.publish_run_connections
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
		FROM control.publish_run_connections WHERE public_url_id = $1 AND publish_run_number = $2 AND state = 'ready'
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

func assertStandaloneUsage(t *testing.T, databaseURL string, database *sql.DB, publicURLID string, publishRunNumber uint64) {
	t.Helper()
	var reportCount int
	var allFinal bool
	var attempts, policyDenials, capacityDenials, publisherFailures, successful, ingressBytes, egressBytes int64
	if err := database.QueryRowContext(integrationOperationContext(t), `
		WITH latest AS (
			SELECT DISTINCT ON (bucket_start)
				final, connection_attempts, policy_denials, capacity_denials,
				visitor_stream_open_failures, successful_streams, ingress_bytes, egress_bytes
			FROM control.ingress_usage_reports
			WHERE public_url_id = $1 AND publish_run_number = $2
			ORDER BY bucket_start, report_revision DESC
		)
		SELECT count(*), coalesce(bool_and(final), false),
			coalesce(sum(connection_attempts), 0), coalesce(sum(policy_denials), 0),
			coalesce(sum(capacity_denials), 0), coalesce(sum(visitor_stream_open_failures), 0),
			coalesce(sum(successful_streams), 0), coalesce(sum(ingress_bytes), 0), coalesce(sum(egress_bytes), 0)
		FROM latest
	`, publicURLID, publishRunNumber).Scan(&reportCount, &allFinal, &attempts, &policyDenials, &capacityDenials, &publisherFailures, &successful, &ingressBytes, &egressBytes); err != nil {
		t.Fatal(err)
	}
	if reportCount == 0 || !allFinal || attempts < 1 || successful < 1 || ingressBytes == 0 || egressBytes == 0 || policyDenials != 0 || capacityDenials != 0 || publisherFailures != 0 {
		t.Fatalf("final usage reports = count %d, final %t, attempts/denials/failures/successes %d/%d/%d/%d/%d, bytes %d/%d",
			reportCount, allFinal, attempts, policyDenials, capacityDenials, publisherFailures, successful, ingressBytes, egressBytes)
	}
	var bucketCount int
	var through time.Time
	if err := database.QueryRowContext(integrationOperationContext(t), `SELECT count(*), max(bucket_end)
		FROM control.public_url_usage_buckets WHERE public_url_id = $1 AND publish_run_number = $2`, publicURLID, publishRunNumber).Scan(&bucketCount, &through); err != nil {
		t.Fatal(err)
	}
	if bucketCount == 0 {
		t.Fatal("public URL usage bucket was not created")
	}
	state, err := controlstate.Open(integrationOperationContext(t), databaseURL, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	finalized, err := state.FinalizePublicURLUsageBuckets(integrationOperationContext(t), through, through)
	if err != nil || finalized != bucketCount {
		t.Fatalf("public URL usage finalization = %d, %v; want %d", finalized, err, bucketCount)
	}
	var allFinalized, allComplete bool
	if err := database.QueryRowContext(integrationOperationContext(t), `SELECT coalesce(bool_and(finalized), false), coalesce(bool_and(complete), false)
		FROM control.public_url_usage_buckets WHERE public_url_id = $1 AND publish_run_number = $2`, publicURLID, publishRunNumber).Scan(&allFinalized, &allComplete); err != nil {
		t.Fatal(err)
	}
	if !allFinalized || !allComplete {
		t.Fatalf("public URL usage buckets = finalized %t, complete %t", allFinalized, allComplete)
	}
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
