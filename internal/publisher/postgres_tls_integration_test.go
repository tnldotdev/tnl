package publisher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationDatabaseClientPostgresMatchingCertificate(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	material := testutil.PostgresTLSFiles(t)
	certificate, err := tls.LoadX509KeyPair(material.CertificateFile, material.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, err := os.ReadFile(material.RootCAFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("invalid disposable PostgreSQL root CA")
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

func TestIntegrationDatabaseClientPostgresEncryptedCancellation(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	material := testutil.PostgresTLSFiles(t)
	certificatePEM, err := os.ReadFile(material.RootCAFile)
	if err != nil {
		t.Fatal(err)
	}
	privateRoots := x509.NewCertPool()
	if !privateRoots.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("invalid disposable PostgreSQL root CA")
	}
	databaseURL := testutil.PostgresURL(t)
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, targetTLS := range []bool{false, true} {
		name := "plaintext target"
		if targetTLS {
			name = "verified TLS target"
		}
		t.Run(name, func(t *testing.T) {
			publicCertificate := publicURLTestCertificate(t, "route.example")
			var plaintextCancels atomic.Int32
			settings := PublicURLServerConfig{
				Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432,
				Target:      parsed.Host,
				Certificate: publicCertificate, OnCancelUnsupported: func() { plaintextCancels.Add(1) },
			}
			if targetTLS {
				settings.TargetTLS, settings.TargetTLSName = true, "db.internal"
				settings.TargetOptions = localproxy.TargetOptions{RootCAs: privateRoots}
			}
			route, err := NewPublicURLServer(settings)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = route.Close() })
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			connection, err := pgx.ConnectConfig(ctx, postgresClientTestConfig(t, route, rootsForCertificate(t, publicCertificate), "disable"))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close(context.Background())
			monitor, err := pgx.Connect(ctx, databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			defer monitor.Close(context.Background())
			pid := connection.PgConn().PID()
			result := make(chan error, 1)
			go func() {
				_, err := connection.Exec(ctx, "SELECT pg_sleep(30)")
				result <- err
			}()
			// wait until the server has started the query so the cancel request
			// cannot race ahead of the backend's active statement.
			for {
				var active bool
				if err := monitor.QueryRow(ctx, `SELECT EXISTS (
					SELECT 1 FROM pg_stat_activity WHERE pid = $1 AND state = 'active' AND query = 'SELECT pg_sleep(30)'
				)`, pid).Scan(&active); err != nil {
					t.Fatal(err)
				}
				if active {
					break
				}
				select {
				case err := <-result:
					t.Fatalf("query finished before cancellation: %v", err)
				case <-time.After(20 * time.Millisecond):
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			if err := connection.PgConn().CancelRequest(ctx); err != nil {
				t.Fatalf("encrypted cancellation request: %v", err)
			}
			select {
			case err := <-result:
				var serverError *pgconn.PgError
				if !errors.As(err, &serverError) || serverError.Code != "57014" {
					t.Fatalf("canceled query = %v, want PostgreSQL 57014", err)
				}
			case <-ctx.Done():
				t.Fatal("query was not canceled: ", ctx.Err())
			}
			var answer int
			if err := connection.QueryRow(ctx, "SELECT 1").Scan(&answer); err != nil || answer != 1 {
				t.Fatalf("connection after cancellation = %d, %v", answer, err)
			}
			if count := plaintextCancels.Load(); count != 0 {
				t.Fatalf("sent %d plaintext cancellation requests", count)
			}
		})
	}
}
