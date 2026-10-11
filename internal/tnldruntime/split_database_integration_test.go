package tnldruntime

import (
	"context"
	"crypto/x509"
	"flag"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/streamcopy"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var splitDatabaseTargetCA = flag.String("tnl-test-postgres-ca", "", "disposable TLS-enabled PostgreSQL target certificate")

func TestIntegrationSplitDatabasePublishAndVisit(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if *splitDatabaseTargetCA == "" {
		t.Skip("requires a disposable TLS-enabled PostgreSQL target")
	}
	backendCertificate, err := os.ReadFile(*splitDatabaseTargetCA)
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
	// simulate the operator verifying one dedicated port on the local ingress
	// address without enabling DNS automation in this split-process fixture.
	if _, err := f.inspect.ExecContext(t.Context(), `UPDATE control.ingress_pools SET ipv4_address = '127.0.0.1'::inet, state = 'enabled', updated_at = GREATEST(updated_at, now()) WHERE id = 'ingress-a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.inspect.ExecContext(t.Context(), `INSERT INTO control.ingress_pool_ports (ingress_pool_id, port, enabled) VALUES ('ingress-a', $1, true)`, publicPortText); err != nil {
		t.Fatal(err)
	}
	quic, tcp := f.connectors()
	config := f.identity.publisherConfig(backendURL.Host, quic, tcp)
	config.ServiceProtocol = controlv1.Postgres
	config.TargetTLSName = "db.internal"
	config.TargetOptions = localproxy.TargetOptions{RootCAs: backendRoots}
	publish := startOwnedIntegrationPublisher(t, f.owner, config, func() string {
		return integrationPublisherDiagnostics(f.inspect, f.pebble.logPath)
	})
	ready := waitForPublisherReady(t, publish)
	if ready.Hostname != f.identity.hostname || ready.PublicURL == "https://"+ready.Hostname {
		t.Fatalf("database publisher readiness = %#v", ready)
	}
	publicHost, portText, err := net.SplitHostPort(ready.PublicURL)
	if err != nil || publicHost != ready.Hostname || portText != publicPortText {
		t.Fatalf("database public address = %q, %v", ready.PublicURL, err)
	}
	waitForReadyPublisherConnections(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber, 2)
	waitForIngressRoutingCurrent(t, f.inspect, 1)
	configPG, err := pgx.ParseConfig("postgres://postgres:postgres@" + ready.PublicURL + "/postgres?sslmode=verify-full&channel_binding=disable")
	if err != nil {
		t.Fatal(err)
	}
	configPG.TLSConfig.RootCAs = f.pebble.roots
	configPG.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	configPG.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", f.ingressConfig.IngressListen)
		if err != nil {
			return nil, err
		}
		source := connection.LocalAddr().(*net.TCPAddr)
		publicPort, err := strconv.Atoi(portText)
		if err != nil {
			connection.Close()
			return nil, err
		}
		header, err := proxyproto.Encode(proxyproto.Header{
			Source:      netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(source.Port)),
			Destination: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(publicPort)),
		})
		if err == nil {
			_, err = connection.Write(header)
		}
		if err != nil {
			connection.Close()
			return nil, err
		}
		return connection, nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	connection, err := pgx.ConnectConfig(ctx, configPG)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if !connection.IsClosed() {
			closeCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			_ = connection.Close(closeCtx)
		}
	}()
	var value int
	if err := connection.QueryRow(ctx, "SELECT $1::int", 1).Scan(&value); err != nil || value != 1 {
		t.Fatalf("split database query = %d, %v", value, err)
	}
	if err := connection.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func startSplitDatabaseChallengeProxy(t *testing.T, publicAddress, ingressAddress string) {
	t.Helper()
	listener, err := net.Listen("tcp", publicAddress)
	if err != nil {
		t.Fatal(err)
	}
	var active sync.WaitGroup
	var mu sync.Mutex
	connections := make(map[net.Conn]struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			visitor, err := listener.Accept()
			if err != nil {
				return
			}
			active.Add(1)
			go func() {
				defer active.Done()
				upstream, err := net.Dial("tcp", ingressAddress)
				if err != nil {
					visitor.Close()
					return
				}
				mu.Lock()
				connections[visitor], connections[upstream] = struct{}{}, struct{}{}
				mu.Unlock()
				defer func() {
					visitor.Close()
					upstream.Close()
					mu.Lock()
					delete(connections, visitor)
					delete(connections, upstream)
					mu.Unlock()
				}()
				source := visitor.RemoteAddr().(*net.TCPAddr)
				header, err := proxyproto.Encode(proxyproto.Header{
					Source:      netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(source.Port)),
					Destination: netip.MustParseAddrPort("127.0.0.1:443"),
				})
				if err != nil {
					return
				}
				if _, err := upstream.Write(header); err != nil {
					return
				}
				_, _ = streamcopy.Copy(visitor, upstream)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-stopped
		mu.Lock()
		for connection := range connections {
			connection.Close()
		}
		mu.Unlock()
		active.Wait()
	})
}
