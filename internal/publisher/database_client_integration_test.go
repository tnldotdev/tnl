package publisher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"flag"
	"net"
	"net/url"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/inspection"
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
	observations := make(chan inspection.Summary, 32)
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432,
		Target: parsed.Host, Certificate: publicCertificate,
		ObserveSummary: func(s inspection.Summary) { observations <- s },
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
	if s := awaitPublisherTest(t, observations); s.Protocol != "postgres" || s.Result != inspection.ResultOK || s.Rows != 1 {
		t.Fatalf("real PostgreSQL summary = %+v", s)
	}
	if _, err := connection.Exec(ctx, "SELECT 1 / 0 /* secret-sql */"); err == nil {
		t.Fatal("division by zero succeeded")
	}
	if s := awaitPublisherTest(t, observations); s.Result != inspection.ResultError || s.SQLState != "22012" {
		t.Fatalf("real PostgreSQL error summary = %+v", s)
	}
	var privateTLS bool
	if err := connection.QueryRow(ctx, "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()").Scan(&privateTLS); err != nil || privateTLS {
		t.Fatalf("private PostgreSQL TLS = %t, %v", privateTLS, err)
	}
	if err := connection.Close(ctx); err != nil {
		t.Fatal(err)
	}
	t.Run("verified target TLS", func(t *testing.T) { exercisePostgresTargetTLS(t, parsed.Host) })
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
	observations := make(chan inspection.Summary, 32)
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Mysql, PublicPort: 3306,
		Target: *testMySQLAddress, Certificate: publicCertificate,
		ObserveSummary: func(s inspection.Summary) { observations <- s },
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
	database, err := sql.Open("mysql", "tnl_client:testpass@"+tlsName+"(route.example:3306)/mysql?tls="+tlsName+"&timeout=10s&readTimeout=10s&writeTimeout=10s")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var value int
	if err := database.QueryRowContext(ctx, "SELECT 1").Scan(&value); err != nil || value != 1 {
		t.Fatalf("MySQL query result = %d, %v", value, err)
	}
	if s := awaitPublisherTest(t, observations); s.Protocol != "mysql" || s.Result != inspection.ResultOK || s.Rows != 1 {
		t.Fatalf("real MySQL summary = %+v", s)
	}
	statement, err := database.PrepareContext(ctx, "SELECT ? /* secret-sql */")
	if err != nil {
		t.Fatal(err)
	}
	defer statement.Close()
	if err := statement.QueryRowContext(ctx, 7).Scan(&value); err != nil || value != 7 {
		t.Fatalf("prepared query = %d, %v", value, err)
	}
	if s := awaitPublisherTest(t, observations); s.Operation != inspection.OperationExecute || s.Rows != 1 {
		t.Fatalf("real MySQL execute summary = %+v", s)
	}
	if _, err := database.ExecContext(ctx, "invalid secret-sql"); err == nil {
		t.Fatal("invalid query succeeded")
	}
	if s := awaitPublisherTest(t, observations); s.Result != inspection.ResultError || s.SQLState != "42000" {
		t.Fatalf("real MySQL error summary = %+v", s)
	}
	var status, cipher string
	if err := database.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Ssl_cipher'").Scan(&status, &cipher); err != nil || status != "Ssl_cipher" || cipher != "" {
		t.Fatalf("private MySQL TLS cipher = %q, %v", cipher, err)
	}
	t.Run("verified target TLS", func(t *testing.T) { exerciseMySQLTargetTLS(t, *testMySQLAddress) })
}
