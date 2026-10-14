package publisher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	projectconfig "github.com/tnldotdev/tnl/internal/config"
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
	observed := make(chan DatabaseObservation, 4)
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432,
		Target: parsed.Host, TargetTLS: true, TargetTLSName: "db.internal", Certificate: certificate,
		TargetOptions:   localproxy.TargetOptions{RootCAs: roots},
		InspectionMode:  projectconfig.InspectionSummary,
		ObserveDatabase: func(value DatabaseObservation) { observed <- value },
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
	select {
	case result := <-observed:
		if result.Protocol != controlv1.Postgres || result.Operation != "execute" || result.Result != "ok" || result.Rows != 1 {
			t.Fatalf("split TLS inspection = %#v", result)
		}
	case <-ctx.Done():
		t.Fatal("split TLS execution was not observed")
	}

	t.Run("different certificates", func(t *testing.T) {
		other := publicURLTestCertificate(t, "route.example")
		route, err := NewPublicURLServer(PublicURLServerConfig{
			Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432,
			Target: parsed.Host, TargetTLS: true, TargetTLSName: "db.internal", Certificate: other,
			TargetOptions: localproxy.TargetOptions{RootCAs: roots},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer route.Close()
		_, err = pgx.ConnectConfig(ctx, postgresClientTestConfig(t, route, rootsForCertificate(t, other), "require"))
		if err == nil || !strings.Contains(err.Error(), "channel_binding=disable") {
			t.Fatalf("different-certificate channel binding diagnosis = %v", err)
		}
	})
}
