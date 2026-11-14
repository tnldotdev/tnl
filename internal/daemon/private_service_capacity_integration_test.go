package daemon

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationPrivatePostgresWithoutPublicCapacity(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	f := newServiceRuntimeFixture(t, false, nil)
	// the isolated fixture has no public inventory; private creation and
	// real PostgreSQL traffic must not repair or allocate that optional capacity.
	if _, err := f.inspect.ExecContext(t.Context(), `DELETE FROM control.ingress_service_port_ranges WHERE ingress_pool_id=$1`, controlstate.PrimaryIngressPoolID); err != nil {
		t.Fatal(err)
	}
	database, err := pgx.ParseConfig(f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	target := net.JoinHostPort(database.Host, strconv.Itoa(int(database.Port)))
	service, err := f.identity.routes.CreateService(t.Context(), f.identity.teamID, "private-postgres", "private-postgres", controlv1.ServiceMetadata{Protocol: controlv1.Postgres})
	if err != nil {
		t.Fatal(err)
	}
	if service.Endpoint == nil || service.Endpoint.Port != 0 || service.Endpoint.Public {
		t.Fatal("private PostgreSQL requires a public reservation", service.Endpoint)
	}
	startPrivateHTTPPublisher(t, f, service, target)
	person, err := f.identity.authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	control, err := connectorstream.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
	if err != nil {
		t.Fatal(err)
	}
	quic, tcp := f.connectors()
	listener, stop := startRuntimeConnector(t, f, service, connectorstream.Config{Control: control, IdentityID: person.Identity.Id, RelayQUIC: quic, RelayTCP: tcp})
	defer stop()
	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	verification := f.visitorRoots.Clone()
	verification.ServerName = service.Endpoint.Hostname
	database.Host, database.Port, database.TLSConfig, database.Fallbacks = host, uint16(number), verification, nil
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	connection, err := pgx.ConnectConfig(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := connection.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	securedConnection, ok := connection.PgConn().Conn().(*tls.Conn)
	if !ok {
		t.Fatal("PostgreSQL did not negotiate visitor TLS")
	}
	secured := securedConnection.ConnectionState()
	if !secured.HandshakeComplete || len(secured.VerifiedChains) == 0 || secured.ServerName != service.Endpoint.Hostname {
		t.Fatal("PostgreSQL did not verify the private service TLS identity")
	}
	tx, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "CREATE TEMP TABLE private_capacity(value integer); INSERT INTO private_capacity VALUES(42)"); err != nil {
		t.Fatal(err)
	}
	var result int
	if err := tx.QueryRow(ctx, "SELECT value FROM private_capacity").Scan(&result); err != nil || result != 42 {
		t.Fatal("private PostgreSQL transaction failed", result, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var claims int
	if err := f.inspect.QueryRowContext(ctx, `SELECT count(*) FROM control.service_port_claims`).Scan(&claims); err != nil || claims != 0 {
		t.Fatal("private PostgreSQL consumed public capacity", claims, err)
	}
}
