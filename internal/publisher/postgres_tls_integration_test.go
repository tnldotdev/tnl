package publisher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationDatabaseClientPostgresMatchingCertificate(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	certificateFile, keyFile := testutil.PostgresTLSFiles(t)
	certificate, err := tls.LoadX509KeyPair(certificateFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, err := os.ReadFile(certificateFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("invalid disposable PostgreSQL certificate")
	}
	parsed, err := url.Parse(testutil.PostgresURL(t))
	if err != nil {
		t.Fatal(err)
	}
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432,
		Target: parsed.Host, TargetTLS: true, TargetTLSName: "db.internal", Certificate: certificate,
		TargetOptions: localproxy.TargetOptions{RootCAs: roots},
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
		t.Fatalf("matching visitor and target certificates did not allow SCRAM-SHA-256-PLUS: %v", err)
	}
	defer connection.Close(context.Background())
	var answer int
	if err := connection.QueryRow(ctx, "SELECT $1::int", 42).Scan(&answer); err != nil || answer != 42 {
		t.Fatalf("shared-certificate query = %d, %v", answer, err)
	}
	var privateTLS bool
	if err := connection.QueryRow(ctx, "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()").Scan(&privateTLS); err != nil || !privateTLS {
		t.Fatalf("private PostgreSQL TLS = %t, %v", privateTLS, err)
	}
}
