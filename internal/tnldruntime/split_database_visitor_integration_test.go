package tnldruntime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationSplitDatabaseVisitorCertificatePromotesBeforePostgresLogin(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) { splitDatabaseVisitorCertificate(t, transport) })
	}
}

func splitDatabaseVisitorCertificate(t *testing.T, transport string) {
	seed := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	f := newSplitPublishFixtureWithOptions(t, "orders", splitPublishOptions{proxyIngress: true, configureProcess: func(c *tnldconfig.Config) {
		if c.Role == tnldconfig.RoleControl {
			c.VisitorIssuerSeed = seed
		}
		if c.Role == tnldconfig.RoleIngress {
			c.RequireProxyHeader = true
		}
	}})
	_, portText, err := net.SplitHostPort(unusedTCPAddress(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.inspect.ExecContext(t.Context(), `UPDATE control.ingress_pools SET ipv4_address = '127.0.0.1'::inet, state = 'enabled' WHERE id = 'ingress-a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.inspect.ExecContext(t.Context(), `INSERT INTO control.ingress_pool_ports (ingress_pool_id, port, enabled) VALUES ('ingress-a', $1, true)`, portText); err != nil {
		t.Fatal(err)
	}
	backend, err := url.Parse(testutil.PostgresURL(t))
	if err != nil {
		t.Fatal(err)
	}
	quic, tcp := f.connectors()
	if transport == "quic" {
		tcp, _ = disabledIntegrationConnector("test QUIC publisher admission")
	} else {
		quic, _ = disabledIntegrationConnector("test TLS/TCP publisher admission")
	}
	publication := f.identity.publisherConfig(backend.Host, quic, tcp)
	publication.ServiceProtocol = controlv1.Postgres
	handle := startOwnedIntegrationPublisher(t, f.owner, publication, func() string { return integrationPublisherDiagnostics(f.inspect, f.pebble.logPath) })
	ready := waitForPublisherReady(t, handle)
	publicHost, publicPort, err := net.SplitHostPort(ready.PublicURL)
	if err != nil || publicPort != portText {
		t.Fatalf("public database address = %q, %v", ready.PublicURL, err)
	}
	waitForReadyPublisherConnections(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber, 2)
	waitForIngressRoutingCurrent(t, f.inspect, 1)

	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, private)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := f.identity.routes.IssueVisitorCertificate(t.Context(), ready.PublicURLID, csr)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	clientCertificate, err := tls.X509KeyPair([]byte(issued.CertificatePem), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	open := func(source string, certificate *tls.Certificate) (*pgx.Conn, error) {
		t.Helper()
		configuration, err := pgx.ParseConfig("postgres://postgres:postgres@" + ready.PublicURL + "/postgres?sslmode=verify-full&channel_binding=disable")
		if err != nil {
			return nil, err
		}
		configuration.TLSConfig.RootCAs = f.pebble.roots
		if certificate != nil {
			configuration.TLSConfig.Certificates = []tls.Certificate{*certificate}
		}
		configuration.Fallbacks = nil
		configuration.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
		configuration.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, "tcp", f.ingressConfig.IngressListen)
			if err != nil {
				return nil, err
			}
			port, _ := strconv.Atoi(portText)
			header, err := proxyproto.Encode(proxyproto.Header{
				Source:      netip.AddrPortFrom(netip.MustParseAddr(source), uint16(c.LocalAddr().(*net.TCPAddr).Port)),
				Destination: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)),
			})
			if err == nil {
				_, err = c.Write(header)
			}
			if err != nil {
				_ = c.Close()
				return nil, fmt.Errorf("forward original visitor address and port: %w", err)
			}
			return c, nil
		}
		ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
		defer cancel()
		return pgx.ConnectConfig(ctx, configuration)
	}
	if publicHost != f.identity.hostname {
		t.Fatal("database URL hostname changed")
	}
	allowed, err := open("127.0.0.1", nil)
	if err != nil {
		t.Fatalf("explicit IP policy lost its separate database visitor path: %v", err)
	}
	_ = allowed.Close(t.Context())
	select {
	case <-handle.done:
		t.Fatalf("publisher stopped before authenticated visitor: %v", handle.result())
	default:
	}
	waitForReadyPublisherConnections(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber, 2)
	visitor, err := open("198.51.100.7", &clientCertificate)
	if err != nil {
		t.Fatalf("current URL-bound certificate did not promote an outside-IP visitor: %v", err)
	}
	defer visitor.Close(context.Background())
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var value int
	if err := visitor.QueryRow(ctx, "SELECT $1::int", 42).Scan(&value); err != nil || value != 42 {
		t.Fatalf("promoted database connection did not reach the target: %d, %v", value, err)
	}
	_ = visitor.Close(ctx)
	if c, err := open("198.51.100.7", nil); err == nil {
		_ = c.Close(t.Context())
		t.Fatal("outside-IP database visitor authenticated without a certificate")
	}
}
