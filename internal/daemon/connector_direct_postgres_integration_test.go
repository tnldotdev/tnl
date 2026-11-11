package daemon

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/peer"
)

func TestIntegrationConnectorDirectRetainsPostgresTransaction(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	f := newServiceRuntimeFixture(t, false, nil)
	database, err := pgx.ParseConfig(f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	target := net.JoinHostPort(database.Host, strconv.Itoa(int(database.Port)))
	observations := connectorDirectObservations(t)
	sockets, packets := connectorDirectSockets(t, f, nil)
	packets[0].blockDirect.Store(true)
	prepared := startConnectorDirectRuntime(t, f, target, sockets, connectorDirectOptions(observations))
	defer prepared.stop()
	host, port, err := net.SplitHostPort(prepared.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	database.Host, database.Port, database.TLSConfig, database.Fallbacks = host, uint16(number), nil, nil
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	connection, err := pgx.ConnectConfig(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close(context.Background()) }()
	tx, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "CREATE TEMP TABLE direct_proof(value integer PRIMARY KEY); SET LOCAL tnl.direct_marker='retained'; SET application_name='connector-direct-proof'"); err != nil {
		t.Fatal(err)
	}
	var originalPID int32
	var originalTransaction int64
	if err := tx.QueryRow(ctx, "SELECT pg_backend_pid(),txid_current()").Scan(&originalPID, &originalTransaction); err != nil {
		t.Fatal(err)
	}
	before := readRebindingObservation(t, f, prepared.service.Id)
	step := 0
	check := func() {
		t.Helper()
		step++
		if _, err := tx.Exec(ctx, "INSERT INTO direct_proof VALUES($1)", step); err != nil {
			t.Fatal("retained transaction insert", err)
		}
		var pid int32
		var transaction int64
		var count int
		var marker, application string
		if err := tx.QueryRow(ctx, "SELECT pg_backend_pid(),txid_current(),current_setting('tnl.direct_marker'),current_setting('application_name'),count(*) FROM direct_proof").Scan(&pid, &transaction, &marker, &application, &count); err != nil {
			t.Fatal("retained transaction query", err)
		}
		if pid != originalPID || transaction != originalTransaction || marker != "retained" || application != "connector-direct-proof" || count != step {
			t.Fatal("delivery change replaced the PostgreSQL backend, transaction, temporary table, or session settings")
		}
	}
	check()
	if packets[0].directDataSent.Load() != 0 || packets[0].directDataRead.Load() != 0 {
		t.Fatal("PostgreSQL startup bypassed the blocked direct path")
	}
	packets[0].blockDirect.Store(false)
	waitConnectorDirectState(t, observations, peer.ConnectivityDirect)
	connectorDirectOnly(t, packets, check)
	packets[0].blockDirect.Store(true)
	check()
	waitConnectorDirectState(t, observations, peer.ConnectivityRelay)
	check()
	packets[0].blockDirect.Store(false)
	waitConnectorDirectState(t, observations, peer.ConnectivityDirect)
	connectorDirectOnly(t, packets, check)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := connection.QueryRow(ctx, "SELECT count(*) FROM direct_proof").Scan(&count); err != nil || count != step {
		t.Fatalf("retained temporary table after commit: count=%d err=%v", count, err)
	}
	assertConnectorDirectOwner(t, f, prepared, before, false)
}
