package publisher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"flag"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	projectconfig "github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var (
	testMySQLAddress = flag.String("tnl-test-mysql-address", "", "disposable MySQL server host and port")
	testMySQLCA      = flag.String("tnl-test-mysql-ca", "", "disposable MySQL server certificate")
	testPostgresCA   = flag.String("tnl-test-postgres-ca", "", "disposable PostgreSQL server certificate")
	testPostgresKey  = flag.String("tnl-test-postgres-key", "", "disposable PostgreSQL server private key for a shared-certificate check")
)

func TestIntegrationDatabaseClientPostgresLogin(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	backendRoots := postgresClientTestRoots(t)
	databaseURL := testutil.PostgresURL(t)
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	publicCertificate := publicURLTestCertificate(t, "route.example")
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432,
		Target: parsed.Host, TargetTLSName: "db.internal", Certificate: publicCertificate,
		TargetOptions: localproxy.TargetOptions{RootCAs: backendRoots},
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
	if err := connection.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationDatabaseClientPostgresMatchingCertificate(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	backendRoots := postgresClientTestRoots(t)
	if *testPostgresKey == "" {
		t.Skip("requires a disposable PostgreSQL target sharing the visitor certificate")
	}
	certificate, err := tls.LoadX509KeyPair(*testPostgresCA, *testPostgresKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(testutil.PostgresURL(t))
	if err != nil {
		t.Fatal(err)
	}
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432,
		Target: parsed.Host, TargetTLSName: "db.internal", Certificate: certificate,
		TargetOptions: localproxy.TargetOptions{RootCAs: backendRoots},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	config := postgresClientTestConfig(t, route, rootsForCertificate(t, certificate), "require")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatalf("shared certificate should allow default PLUS authentication: %v", err)
	}
	defer connection.Close(context.Background())
	var value int
	if err := connection.QueryRow(ctx, "SELECT $1::int", 1).Scan(&value); err != nil || value != 1 {
		t.Fatalf("shared certificate query = %d, %v", value, err)
	}
}

func TestIntegrationDatabaseClientPostgresInspection(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	backendRoots := postgresClientTestRoots(t)
	parsed, err := url.Parse(testutil.PostgresURL(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []projectconfig.RequestInspectionMode{projectconfig.RequestInspectionSummary, projectconfig.RequestInspectionDetailed} {
		t.Run(string(mode), func(t *testing.T) {
			observed := make(chan DatabaseObservation, 8)
			certificate := publicURLTestCertificate(t, "route.example")
			route, err := NewPublicURLServer(PublicURLServerConfig{
				Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432,
				Target: parsed.Host, TargetTLSName: "db.internal", Certificate: certificate,
				TargetOptions:     localproxy.TargetOptions{RootCAs: backendRoots},
				RequestInspection: mode,
				ObserveDatabase:   func(value DatabaseObservation) { observed <- value },
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
				t.Fatalf("query = %d, %v", value, err)
			}
			if _, err := connection.Exec(ctx, "SELECT missing_column"); err == nil {
				t.Fatal("expected a PostgreSQL query failure")
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
			if success.Operation != "execute" || success.Result != "ok" || success.Rows != 1 ||
				failed.Result != "error" || failed.SQLState != "42703" {
				t.Fatalf("database observations = %#v, %#v", success, failed)
			}
			if mode == projectconfig.RequestInspectionSummary && (success.Statement != "" || failed.Statement != "") {
				t.Fatal("summary inspection stored SQL")
			}
			if mode == projectconfig.RequestInspectionDetailed && (success.Statement != "SELECT $1::int" || failed.Statement != "SELECT missing_column") {
				t.Fatalf("detailed inspection did not capture statements: %#v, %#v", success, failed)
			}
		})
	}
}

func postgresClientTestRoots(t *testing.T) *x509.CertPool {
	t.Helper()
	if *testPostgresCA == "" {
		t.Skip("requires the PostgreSQL TLS integration target")
	}
	certificate, err := os.ReadFile(*testPostgresCA)
	if err != nil {
		t.Fatalf("read disposable PostgreSQL certificate: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		t.Fatal("invalid disposable PostgreSQL certificate")
	}
	return roots
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
	if *testMySQLAddress == "" && *testMySQLCA == "" {
		t.Skip("requires the MySQL integration target")
	}
	if *testMySQLAddress == "" || *testMySQLCA == "" {
		t.Fatal("MySQL integration requires a disposable server and certificate")
	}
	certificatePEM, err := os.ReadFile(*testMySQLCA)
	if err != nil {
		t.Fatal(err)
	}
	backendRoots := x509.NewCertPool()
	if !backendRoots.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("invalid disposable MySQL certificate")
	}
	publicCertificate := publicURLTestCertificate(t, "route.example")
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Mysql, PublicPort: 3306,
		Target: *testMySQLAddress, TargetTLSName: "db.internal", Certificate: publicCertificate,
		TargetOptions: localproxy.TargetOptions{RootCAs: backendRoots},
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
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	database, err := sql.Open("mysql", "root:testpass@"+tlsName+"(route.example:3306)/mysql?tls="+tlsName+"&timeout=10s&readTimeout=10s&writeTimeout=10s")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var value int
	if err := database.QueryRowContext(ctx, "SELECT 1").Scan(&value); err != nil || value != 1 {
		t.Fatalf("MySQL query result = %d, %v", value, err)
	}
}

func TestIntegrationDatabaseClientPostgresChannelBinding(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	roots := postgresClientTestRoots(t)
	address := testutil.PostgresURL(t)
	parsed, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432,
		Target: parsed.Host, DatabaseTLSPassthrough: true, Certificate: publicURLTestCertificate(t, "route.example"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	config := postgresClientTestConfig(t, route, roots, "require")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	var value int
	if err := connection.QueryRow(ctx, "SELECT 1").Scan(&value); err != nil || value != 1 {
		t.Fatalf("SCRAM-SHA-256-PLUS query result = %d, %v", value, err)
	}
	if err := connection.Close(ctx); err != nil {
		t.Fatal(err)
	}
	publicCertificate := publicURLTestCertificate(t, "route.example")
	backend, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432,
		Target: parsed.Host, TargetTLSName: "db.internal", Certificate: publicCertificate,
		TargetOptions: localproxy.TargetOptions{RootCAs: roots},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	separatedRoots := rootsForCertificate(t, publicCertificate)
	withoutBinding := postgresClientTestConfig(t, backend, separatedRoots, "disable")
	withoutBindingCtx, cancelWithoutBinding := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancelWithoutBinding()
	connection, err = pgx.ConnectConfig(withoutBindingCtx, withoutBinding)
	if err != nil {
		t.Fatalf("separate TLS login without channel binding: %v", err)
	}
	if err := connection.Close(withoutBindingCtx); err != nil {
		t.Fatal(err)
	}
	required := postgresClientTestConfig(t, backend, separatedRoots, "require")
	requiredCtx, cancelRequired := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancelRequired()
	connection, err = pgx.ConnectConfig(requiredCtx, required)
	if err == nil {
		_ = connection.Close(requiredCtx)
		t.Fatal("SCRAM-SHA-256-PLUS unexpectedly crossed two different TLS channels")
	}
	var authError *pgconn.PgError
	if requiredCtx.Err() != nil || !errors.As(err, &authError) || authError.Code != "28000" ||
		!strings.Contains(authError.Message, "channel_binding=disable") ||
		!strings.Contains(authError.Message, "--database-tls-passthrough") {
		t.Fatalf("separate TLS channel binding failure = %v, context = %v", err, requiredCtx.Err())
	}
}
