package publisher_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func postgresManagedFixture(t *testing.T) (publisher.ServiceStream, endpointFixture) {
	t.Helper()
	if *managedPostgresAddress == "" {
		t.Fatal("use go:test:integration:tcp-clients with its disposable TLS PostgreSQL")
	}
	ca, err := os.ReadFile(*managedPostgresCA)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid provider CA")
	}
	certificates := serviceCertificates(t)
	return publisher.ServiceStream{Protocol: config.ProtocolPostgres, Hostname: "orders.production.storefront.example.test", Target: *managedPostgresAddress,
		TLS:       &tls.Config{Certificates: []tls.Certificate{certificates.server}, MinVersion: tls.VersionTLS12},
		TargetTLS: &tls.Config{RootCAs: roots, ServerName: *managedPostgresHostname, MinVersion: tls.VersionTLS12},
		Visitor: publisher.ConnectorVisitor{Admission: publisher.NativeAdmissionFixture{Check: func(context.Context) (publisher.ServiceVisitorDecision, error) {
			return publisher.ServiceVisitorDecision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
		}}}}, certificates
}

func managedPGConnect(t *testing.T, address string, verification *tls.Config) *pgx.Conn {
	t.Helper()
	configuration, err := pgx.ParseConfig("postgres://tnl_client:testpass@" + address + "/tnl_fixture?sslmode=disable&channel_binding=disable")
	if err != nil {
		t.Fatal(err)
	}
	configuration.TLSConfig, configuration.Fallbacks = verification, nil
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := pgx.ConnectConfig(ctx, configuration)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(context.Background()) })
	return client
}

func waitPGSleep(t *testing.T, observer *pgx.Conn, pid uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		var sleeping bool
		if err := observer.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event='PgSleep')", pid).Scan(&sleeping); err != nil {
			t.Fatal(err)
		}
		if sleeping {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("query never reached PostgreSQL PgSleep")
}

// these are negative authorization probes, not native client cancellation support.
// both services deliberately share a provider so an unbound backend key is useful
// across service boundaries. no raw opaque TCP forwarding is involved.
func TestIntegrationManagedPostgresCancelOwnership(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, mode := range []string{"plaintext", "other-principal", "other-service"} {
		t.Run(mode, func(t *testing.T) {
			server, certificates := postgresManagedFixture(t)
			server.Visitor = publisher.CertificateVisitor{Check: func(_ context.Context, leaf *x509.Certificate) (publisher.ServiceVisitorDecision, error) {
				// each leaf represents an independently admitted principal. possession
				// of either leaf must not authorize the other principal's cancel key.
				return publisher.ServiceVisitorDecision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
			}}
			verification := &tls.Config{RootCAs: certificates.roots, ServerName: server.Hostname, Certificates: []tls.Certificate{certificates.client}, MinVersion: tls.VersionTLS12}
			address := managedIngressListener(t, server)
			client := managedPGConnect(t, address, verification)
			observer := managedPGConnect(t, address, verification)
			if _, err := client.Exec(t.Context(), "CREATE TEMP SEQUENCE cancel_attempt; SET statement_timeout='1800ms'"); err != nil {
				t.Fatal(err)
			}
			pid, secret := client.PgConn().PID(), client.PgConn().SecretKey()
			done := make(chan error, 1)
			go func() {
				_, err := client.Exec(t.Context(), "SELECT nextval('cancel_attempt'); SELECT pg_sleep(10)")
				done <- err
			}()
			waitPGSleep(t, observer, pid)
			cancelTLS := verification.Clone()
			if mode == "other-service" {
				server.Hostname = "sibling.production.storefront.example.test"
				cancelTLS.ServerName = server.Hostname
				address = managedIngressListener(t, server)
			} else if mode == "other-principal" {
				cancelTLS.Certificates = []tls.Certificate{serviceCertificates(t).client}
			}
			conn, err := net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			if mode != "plaintext" {
				_, err = conn.Write([]byte{0, 0, 0, 8, 4, 210, 22, 47})
				var reply [1]byte
				if err == nil {
					_, err = io.ReadFull(conn, reply[:])
				}
				if err != nil || reply[0] != 'S' {
					t.Fatal("SSLRequest failed", err)
				}
				secured := tls.Client(conn, cancelTLS)
				if err := secured.HandshakeContext(t.Context()); err != nil {
					t.Fatal(err)
				}
				conn = secured
			}
			packet := binary.BigEndian.AppendUint32(nil, 16)
			packet = binary.BigEndian.AppendUint32(packet, 80877102)
			packet = binary.BigEndian.AppendUint32(packet, pid)
			packet = append(packet, secret...)
			_, _ = conn.Write(packet)
			var reply [1]byte
			_, _ = conn.Read(reply[:])
			_ = conn.Close()
			// the independent connection continues while the intended query sleeps.
			var one int
			if err := observer.QueryRow(t.Context(), "SELECT 1").Scan(&one); err != nil || one != 1 {
				t.Fatal("cancel probe damaged independent connection", err)
			}
			select {
			case err := <-done:
				var pgError *pgconn.PgError
				if !errors.As(err, &pgError) || pgError.Code != "57014" || !strings.Contains(pgError.Message, "statement timeout") {
					t.Fatalf("unbound %s cancel interrupted another session: %v", mode, err)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("statement timeout did not bound native query")
			}
			var attempts int
			if err := client.QueryRow(t.Context(), "SELECT last_value FROM cancel_attempt").Scan(&attempts); err != nil || attempts != 1 || client.PgConn().PID() != pid {
				t.Fatal("query replayed or original connector session was replaced", attempts, err)
			}
			t.Log("real ingress -> ServiceStream postgres -> verified provider TLS: unbound cancel refused; PgSleep ended only at statement_timeout; same PID, one execution, independent session usable")
		})
	}
}
