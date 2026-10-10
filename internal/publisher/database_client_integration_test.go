package publisher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"flag"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/streamcopy"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var (
	testMySQLAddress = flag.String("tnl-test-mysql-address", "", "disposable MySQL server host and port")
	testMySQLCA      = flag.String("tnl-test-mysql-ca", "", "disposable MySQL server certificate")
	testPostgresCA   = flag.String("tnl-test-postgres-ca", "", "disposable PostgreSQL server certificate")
)

func TestIntegrationDatabaseClientPostgresLogin(t *testing.T) {
	databaseURL := testutil.PostgresURL(t)
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	publicCertificate := publicURLTestCertificate(t, "route.example")
	backendCertificate := publicURLTestCertificate(t, "db.internal")
	backendRoots := x509.NewCertPool()
	backendRoots.AddCert(backendCertificate.Leaf)
	backend, backendDone := postgresTLSTarget(t, parsed.Host, backendCertificate)
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432,
		Target: backend, TargetTLSName: "db.internal", Certificate: publicCertificate,
		TargetOptions: localproxy.TargetOptions{RootCAs: backendRoots},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	roots := x509.NewCertPool()
	roots.AddCert(publicCertificate.Leaf)
	config, err := pgx.ParseConfig("postgres://postgres:postgres@route.example:5432/postgres?sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	config.TLSConfig.RootCAs = roots
	config.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	config.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		visitor, publisher := net.Pipe()
		_ = visitor.SetDeadline(time.Now().Add(10 * time.Second))
		go route.handleVisitor(publisher, false)
		header, err := proxyproto.Encode(proxyproto.Header{
			Source: netip.MustParseAddrPort("192.0.2.10:40001"), Destination: netip.MustParseAddrPort("203.0.113.10:5432"),
		})
		if err == nil {
			_, err = visitor.Write(header)
		}
		if err != nil {
			_ = visitor.Close()
			return nil, err
		}
		return visitor, nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	var value int
	if err := connection.QueryRow(ctx, "SELECT 1").Scan(&value); err != nil || value != 1 {
		t.Fatalf("database query result = %d, %v", value, err)
	}
	if err := connection.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-backendDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("private PostgreSQL forwarding did not finish")
	}
}

func postgresTLSTarget(t *testing.T, address string, certificate tls.Certificate) (string, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	result := make(chan error, 1)
	go func() {
		visitor, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer visitor.Close()
		_ = visitor.SetDeadline(time.Now().Add(10 * time.Second))
		var startup [8]byte
		if _, err := io.ReadFull(visitor, startup[:]); err != nil || startup != postgresSSLRequest {
			result <- errors.New("private target received a non-SSL PostgreSQL startup")
			return
		}
		if _, err := visitor.Write([]byte{'S'}); err != nil {
			result <- err
			return
		}
		secured := tls.Server(visitor, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		if err := secured.Handshake(); err != nil {
			result <- err
			return
		}
		plain, err := net.DialTimeout("tcp", address, 3*time.Second)
		if err != nil {
			result <- err
			return
		}
		defer plain.Close()
		_ = visitor.SetDeadline(time.Time{})
		_, err = streamcopy.Copy(secured, plain)
		result <- err
	}()
	return listener.Addr().String(), result
}

func TestIntegrationDatabaseClientMySQLLogin(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierMySQL)
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
	visitorRoots := x509.NewCertPool()
	visitorRoots.AddCert(publicCertificate.Leaf)
	const tlsName = "tnl-test-database-mysql"
	if err := mysql.RegisterTLSConfig(tlsName, &tls.Config{
		ServerName: "route.example", RootCAs: visitorRoots, MinVersion: tls.VersionTLS12,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mysql.DeregisterTLSConfig(tlsName) })
	mysql.RegisterDialContext(tlsName, func(ctx context.Context, _ string) (net.Conn, error) {
		visitor, publisher := net.Pipe()
		_ = visitor.SetDeadline(time.Now().Add(10 * time.Second))
		go route.handleVisitor(publisher, false)
		header, err := proxyproto.Encode(proxyproto.Header{
			Source: netip.MustParseAddrPort("192.0.2.10:40001"), Destination: netip.MustParseAddrPort("203.0.113.10:3306"),
		})
		if err == nil {
			_, err = visitor.Write(header)
		}
		if err != nil {
			_ = visitor.Close()
			return nil, err
		}
		return visitor, nil
	})
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
	if *testPostgresCA == "" {
		t.Skip("requires the PostgreSQL TLS integration target")
	}
	address := testutil.PostgresURL(t)
	parsed, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	certificate, err := os.ReadFile(*testPostgresCA)
	if err != nil || !roots.AppendCertsFromPEM(certificate) {
		t.Fatalf("read disposable PostgreSQL certificate: %v", err)
	}
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432,
		Target: parsed.Host, DatabaseTLSPassthrough: true, Certificate: publicURLTestCertificate(t, "route.example"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	config, err := pgx.ParseConfig("postgres://postgres:postgres@route.example:5432/postgres?sslmode=verify-full&channel_binding=require")
	if err != nil {
		t.Fatal(err)
	}
	config.TLSConfig.RootCAs = roots
	config.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	config.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		visitor, publisher := net.Pipe()
		_ = visitor.SetDeadline(time.Now().Add(10 * time.Second))
		go route.handleVisitor(publisher, false)
		header, err := proxyproto.Encode(proxyproto.Header{
			Source: netip.MustParseAddrPort("192.0.2.10:40001"), Destination: netip.MustParseAddrPort("203.0.113.10:5432"),
		})
		if err == nil {
			_, err = visitor.Write(header)
		}
		if err != nil {
			_ = visitor.Close()
			return nil, err
		}
		return visitor, nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
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
		Target: parsed.Host, TargetTLSName: "route.example", Certificate: publicCertificate,
		TargetOptions: localproxy.TargetOptions{RootCAs: roots},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	visitorRoots := x509.NewCertPool()
	visitorRoots.AddCert(publicCertificate.Leaf)
	separated := config.Copy()
	separated.TLSConfig = config.TLSConfig.Clone()
	separated.TLSConfig.RootCAs = visitorRoots
	separated.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		visitor, publisher := net.Pipe()
		_ = visitor.SetDeadline(time.Now().Add(10 * time.Second))
		go backend.handleVisitor(publisher, false)
		header, err := proxyproto.Encode(proxyproto.Header{
			Source: netip.MustParseAddrPort("192.0.2.10:40001"), Destination: netip.MustParseAddrPort("203.0.113.10:5432"),
		})
		if err == nil {
			_, err = visitor.Write(header)
		}
		if err != nil {
			_ = visitor.Close()
			return nil, err
		}
		return visitor, nil
	}
	if connection, err := pgx.ConnectConfig(ctx, separated); err == nil {
		_ = connection.Close(ctx)
		t.Fatal("SCRAM-SHA-256-PLUS unexpectedly crossed two different TLS channels")
	}
}
