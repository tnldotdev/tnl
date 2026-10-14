package publisher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"flag"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	projectconfig "github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var (
	testMySQLAddress = flag.String("tnl-test-mysql-address", "", "disposable MySQL server host and port")
)

func TestIntegrationDatabaseClientPostgresLogin(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	databaseURL := testutil.PostgresURL(t)
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	publicCertificate := publicURLTestCertificate(t, "route.example")
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432,
		Target: parsed.Host, Certificate: publicCertificate,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	config := postgresClientTestConfig(t, route, rootsForCertificate(t, publicCertificate), "disable")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	var value int
	if err := connection.QueryRow(ctx, "SELECT 1").Scan(&value); err != nil || value != 1 {
		t.Fatalf("database query result = %d, %v", value, err)
	}
	var privateTLS bool
	if err := connection.QueryRow(ctx, "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()").Scan(&privateTLS); err != nil || privateTLS {
		t.Fatalf("private PostgreSQL TLS = %t, %v", privateTLS, err)
	}
	if err := connection.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationDatabaseClientPostgresInspection(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	parsed, err := url.Parse(testutil.PostgresURL(t))
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan DatabaseObservation, 8)
	certificate := publicURLTestCertificate(t, "route.example")
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432,
		Target: parsed.Host, Certificate: certificate, InspectionMode: projectconfig.InspectionSummary,
		ObserveDatabase: func(value DatabaseObservation) { observed <- value },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	connection, err := pgx.ConnectConfig(ctx, postgresClientTestConfig(t, route, rootsForCertificate(t, certificate), "disable"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	var value int
	if err := connection.QueryRow(ctx, "SELECT $1::int", 1).Scan(&value); err != nil || value != 1 {
		t.Fatalf("prepared query = %d, %v", value, err)
	}
	if _, err := connection.Exec(ctx, "SELECT missing_column"); err == nil {
		t.Fatal("expected PostgreSQL SQL error")
	}
	var success, failed DatabaseObservation
	select {
	case success = <-observed:
	case <-ctx.Done():
		t.Fatal("successful execution was not observed")
	}
	select {
	case failed = <-observed:
	case <-ctx.Done():
		t.Fatal("failed execution was not observed")
	}
	if success.Protocol != controlv1.Postgres || success.Operation != "execute" || success.Result != "ok" || success.Rows != 1 ||
		failed.Result != "error" || failed.SQLState != "42703" {
		t.Fatalf("PostgreSQL observations = %#v, %#v", success, failed)
	}
}

func postgresClientTestConfig(t *testing.T, route *PublicURLServer, roots *x509.CertPool, channelBinding string) *pgx.ConnConfig {
	t.Helper()
	address := "postgres://postgres:postgres@route.example:5432/postgres?sslmode=verify-full&channel_binding=" + channelBinding
	config, err := pgx.ParseConfig(address)
	if err != nil {
		t.Fatal(err)
	}
	config.TLSConfig.RootCAs = roots
	config.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	config.DialFunc = func(context.Context, string, string) (net.Conn, error) {
		return dialDatabaseVisitor(t, route, 5432)
	}
	return config
}

func TestIntegrationDatabaseClientMySQLLogin(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if *testMySQLAddress == "" {
		t.Skip("requires the MySQL integration target")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	publicCertificate := publicURLTestCertificate(t, "route.example")
	var observationsMu sync.Mutex
	var observations []DatabaseObservation
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Mysql, PublicPort: 3306,
		Target: *testMySQLAddress, Certificate: publicCertificate,
		InspectionMode: projectconfig.InspectionSummary,
		ObserveDatabase: func(value DatabaseObservation) {
			observationsMu.Lock()
			observations = append(observations, value)
			observationsMu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	const tlsName = "tnl-test-database-mysql"
	if err := mysql.RegisterTLSConfig(tlsName, &tls.Config{
		ServerName: "route.example", RootCAs: rootsForCertificate(t, publicCertificate), MinVersion: tls.VersionTLS12,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mysql.DeregisterTLSConfig(tlsName) })
	mysql.RegisterDialContext(tlsName, func(context.Context, string) (net.Conn, error) {
		return dialDatabaseVisitor(t, route, 3306)
	})
	t.Cleanup(func() { mysql.DeregisterDialContext(tlsName) })
	database, err := sql.Open("mysql", "tnl_client:testpass@"+tlsName+"(route.example:3306)/mysql?tls="+tlsName+"&timeout=10s&readTimeout=10s&writeTimeout=10s&multiStatements=true")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var value int
	if err := database.QueryRowContext(ctx, "SELECT 1").Scan(&value); err != nil || value != 1 {
		t.Fatalf("MySQL query result = %d, %v", value, err)
	}
	var status, cipher string
	if err := database.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Ssl_cipher'").Scan(&status, &cipher); err != nil || status != "Ssl_cipher" || cipher != "" {
		t.Fatalf("private MySQL TLS cipher = %q, %v", cipher, err)
	}
	statement, err := database.PrepareContext(ctx, "SELECT ?")
	if err != nil {
		t.Fatal(err)
	}
	if err := statement.QueryRowContext(ctx, 23).Scan(&value); err != nil || value != 23 {
		t.Fatalf("prepared query = %d, %v", value, err)
	}
	if err := statement.Close(); err != nil {
		t.Fatal(err)
	}
	rows, err := database.QueryContext(ctx, "SELECT 1; SELECT 2")
	if err != nil {
		t.Fatal(err)
	}
	for expected := 1; expected <= 2; expected++ {
		if !rows.Next() {
			t.Fatalf("missing result set %d: %v", expected, rows.Err())
		}
		if err := rows.Scan(&value); err != nil || value != expected {
			t.Fatalf("result set %d = %d, %v", expected, value, err)
		}
		if rows.Next() || rows.Err() != nil {
			t.Fatalf("unexpected extra row in result set %d: %v", expected, rows.Err())
		}
		if expected < 2 && !rows.NextResultSet() {
			t.Fatalf("missing second result set: %v", rows.Err())
		}
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, "SELECT missing_column").Scan(&value); err == nil {
		t.Fatal("expected MySQL SQL error")
	}
	observationsMu.Lock()
	defer observationsMu.Unlock()
	if len(observations) != 5 {
		t.Fatalf("observed %d MySQL executions: %#v", len(observations), observations)
	}
	if observations[2].Operation != "execute" || observations[2].Rows != 1 ||
		observations[3].ResultSets != 2 || observations[3].Rows != 2 || observations[4].Result != "error" ||
		observations[4].MySQLErrorCode != 1054 || observations[4].SQLState != "42S22" {
		t.Fatalf("MySQL execution attribution = %#v", observations)
	}
}
