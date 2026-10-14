package tnldruntime

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationSplitDatabasePublishAndVisit(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	material := testutil.PostgresTLSFiles(t)
	backendCertificate, err := os.ReadFile(material.RootCAFile)
	if err != nil {
		t.Fatal(err)
	}
	backendRoots := x509.NewCertPool()
	if !backendRoots.AppendCertsFromPEM(backendCertificate) {
		t.Fatal("invalid database target certificate")
	}
	backendURL, err := url.Parse(testutil.PostgresURL(t))
	if err != nil {
		t.Fatal(err)
	}
	_, publicPortText, err := net.SplitHostPort(unusedTCPAddress(t))
	if err != nil {
		t.Fatal(err)
	}
	f := newSplitPublishFixtureWithOptions(t, "orders", splitPublishOptions{proxyIngress: true})
	// the test owns the selected public port before adding it to the disposable
	// ingress pool, equivalent to the operator inventory in a real deployment.
	if _, err := f.inspect.ExecContext(t.Context(), `UPDATE control.ingress_pools SET ipv4_address = '127.0.0.1'::inet, state = 'enabled', updated_at = GREATEST(updated_at, now()) WHERE id = 'ingress-a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.inspect.ExecContext(t.Context(), `INSERT INTO control.ingress_pool_ports (ingress_pool_id, port, enabled) VALUES ('ingress-a', $1, true)`, publicPortText); err != nil {
		t.Fatal(err)
	}
	quic, tcp := f.connectors()
	config := f.identity.publisherConfig(backendURL.Host, quic, tcp)
	config.ServiceProtocol = controlv1.Postgres
	config.TargetTLS = true
	config.TargetTLSName = "db.internal"
	config.TargetOptions = localproxy.TargetOptions{RootCAs: backendRoots}
	publish := startOwnedIntegrationPublisher(t, f.owner, config, func() string {
		return integrationPublisherDiagnostics(f.inspect, f.pebble.logPath)
	})
	ready := waitForPublisherReady(t, publish)
	publicHost, portText, err := net.SplitHostPort(ready.PublicURL)
	if err != nil || publicHost != f.identity.hostname || portText != publicPortText {
		t.Fatalf("database public address = %q, %v", ready.PublicURL, err)
	}
	waitForReadyPublisherConnections(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber, 2)
	waitForIngressRoutingCurrent(t, f.inspect, 1)
	configPG, err := pgx.ParseConfig("postgres://postgres:postgres@" + ready.PublicURL + "/postgres?sslmode=verify-full&channel_binding=disable")
	if err != nil {
		t.Fatal(err)
	}
	configPG.TLSConfig.RootCAs = f.pebble.roots
	configPG.Fallbacks = nil
	configPG.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	configPG.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", f.ingressConfig.IngressListen)
		if err != nil {
			return nil, err
		}
		source := connection.LocalAddr().(*net.TCPAddr)
		port, err := strconv.Atoi(portText)
		if err != nil {
			connection.Close()
			return nil, err
		}
		header, err := proxyproto.Encode(proxyproto.Header{
			Source:      netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(source.Port)),
			Destination: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)),
		})
		if err == nil {
			_, err = connection.Write(header)
		}
		if err != nil {
			connection.Close()
			return nil, fmt.Errorf("forward visitor destination port: %w", err)
		}
		return connection, nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	connection, err := pgx.ConnectConfig(ctx, configPG)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	var answer int
	if err := connection.QueryRow(ctx, "SELECT $1::int", 42).Scan(&answer); err != nil || answer != 42 {
		t.Fatalf("split database query = %d, %v", answer, err)
	}
	var privateTLS bool
	if err := connection.QueryRow(ctx, "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()").Scan(&privateTLS); err != nil || !privateTLS {
		t.Fatalf("private PostgreSQL TLS = %t, %v", privateTLS, err)
	}
	if err := connection.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
