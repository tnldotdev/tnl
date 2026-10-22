package publisher_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/targettransport"
	"github.com/tnldotdev/tnl/internal/testutil"
)

var managedPostgresAddress = flag.String("tnl-test-postgres-address", "", "disposable TLS PostgreSQL target address")
var managedPostgresCA = flag.String("tnl-test-postgres-ca-file", "", "disposable TLS PostgreSQL CA file")
var managedPostgresHostname = flag.String("tnl-test-postgres-tls-hostname", "", "disposable TLS PostgreSQL certificate hostname")
var managedMySQLAddress = flag.String("tnl-test-mysql-address", "", "disposable TLS MySQL target address")
var managedMySQLCA = flag.String("tnl-test-mysql-ca-file", "", "disposable TLS MySQL CA file")
var managedMySQLHostname = flag.String("tnl-test-mysql-tls-hostname", "", "disposable TLS MySQL certificate hostname")
var managedPostgresClient = flag.String("tnl-test-postgres-client-container", "", "disposable provider container owning the real psql client")
var managedMySQLClient = flag.String("tnl-test-mysql-client-container", "", "disposable provider container owning the real mysql client")

type managedTLSFixture struct {
	server, client tls.Certificate
	wrongName      tls.Certificate
	roots          *x509.CertPool
	ca             []byte
}

func managedCertificates(t *testing.T) managedTLSFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "managed provider fixture issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(serial int64, usage x509.ExtKeyUsage, names []string) tls.Certificate {
		t.Helper()
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: fmt.Sprintf("managed provider fixture %d", serial)}, DNSNames: names, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		encoded, err := x509.CreateCertificate(rand.Reader, leaf, ca, &private.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{encoded, der}, PrivateKey: private}
	}
	return managedTLSFixture{server: issue(2, x509.ExtKeyUsageServerAuth, []string{"*.production.storefront.example.test"}), client: issue(3, x509.ExtKeyUsageClientAuth, nil), wrongName: issue(4, x509.ExtKeyUsageServerAuth, []string{"wrong.example.test"}), roots: roots, ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func managedPublisherListener(t *testing.T, server publisher.ManagedStream, addresses ...string) string {
	t.Helper()
	address := "127.0.0.1:0"
	if len(addresses) != 0 {
		address = addresses[0]
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Go(func() { defer client.Close(); _ = server.Forward(ctx, client) })
		}
	})
	t.Cleanup(func() { cancel(); _ = listener.Close(); workers.Wait() })
	return listener.Addr().String()
}

func TestIntegrationManagedDatabaseProviders(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	selected := false
	for _, setting := range []struct {
		protocol              config.ProtocolName
		address, hostname, ca *string
	}{
		{config.ProtocolPostgres, managedPostgresAddress, managedPostgresHostname, managedPostgresCA},
		{config.ProtocolMySQL, managedMySQLAddress, managedMySQLHostname, managedMySQLCA},
	} {
		if *setting.address == "" {
			continue
		}
		selected = true
		t.Run(string(setting.protocol), func(t *testing.T) {
			ca, err := os.ReadFile(*setting.ca)
			if err != nil {
				t.Fatal(err)
			}
			targetRoots := x509.NewCertPool()
			if !targetRoots.AppendCertsFromPEM(ca) {
				t.Fatal("target CA invalid")
			}
			certificates := managedCertificates(t)
			const host = "orders.production.storefront.example.test"
			server := publisher.ManagedStream{Protocol: setting.protocol, Hostname: host, Target: *setting.address,
				TLS:       &tls.Config{Certificates: []tls.Certificate{certificates.server}, MinVersion: tls.VersionTLS12},
				TargetTLS: &tls.Config{RootCAs: targetRoots, ServerName: *setting.hostname, MinVersion: tls.VersionTLS12},
				Visitor: publisher.CertificateVisitor{Check: func(_ context.Context, leaf *x509.Certificate) (publisher.ManagedVisitorDecision, error) {
					_, err := leaf.Verify(x509.VerifyOptions{Roots: certificates.roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
					return publisher.ManagedVisitorDecision{Allowed: err == nil, ValidUntil: time.Now().Add(time.Minute)}, err
				}}}
			clientTLS := &tls.Config{RootCAs: certificates.roots, ServerName: host, Certificates: []tls.Certificate{certificates.client}, MinVersion: tls.VersionTLS12}
			for _, direct := range []bool{false, true} {
				t.Run(fmt.Sprintf("native-command/direct=%t", direct), func(t *testing.T) {
					front := server
					if !direct {
						front.Visitor = publisher.ConnectorVisitor{Check: func(context.Context) (publisher.ManagedVisitorDecision, error) {
							return publisher.ManagedVisitorDecision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
						}}
					}
					address := managedPublisherListener(t, front, "0.0.0.0:0")
					container := *managedPostgresClient
					if setting.protocol == config.ProtocolMySQL {
						container = *managedMySQLClient
					}
					runNativeDatabaseCommand(t, setting.protocol, container, address, certificates, direct)
				})
			}
			t.Run("publisher-native-preflight", func(t *testing.T) {
				transport := targettransport.Transport{Protocol: setting.protocol, TLS: server.TargetTLS}
				if err := transport.Preflight(t.Context(), server.Target); err != nil {
					t.Fatal(err)
				}
				for _, invalid := range []string{"hostname", "CA"} {
					wrong := transport
					wrong.TLS = transport.TLS.Clone()
					if invalid == "hostname" {
						wrong.TLS.ServerName = "wrong.target.test"
					} else {
						wrong.TLS.RootCAs = certificates.roots
					}
					err := wrong.Preflight(t.Context(), server.Target)
					reason, definition, ok := failure.Describe(err)
					var certificate *tls.CertificateVerificationError
					if !ok || reason != failure.TargetTLSRejected || definition.Retry != failure.RetryAfterChange || !errors.As(err, &certificate) {
						t.Fatalf("%s preflight lost certificate rejection: %v", invalid, err)
					}
				}
			})
			query := func(address string, verification *tls.Config) error {
				ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
				defer cancel()
				if setting.protocol == config.ProtocolPostgres {
					configuration, err := pgx.ParseConfig("postgres://tnl_client:testpass@" + address + "/tnl_fixture?sslmode=disable&channel_binding=disable")
					if err != nil {
						return err
					}
					configuration.TLSConfig, configuration.Fallbacks = verification, nil
					connection, err := pgx.ConnectConfig(ctx, configuration)
					if err != nil {
						return err
					}
					defer connection.Close(context.WithoutCancel(ctx))
					var user string
					var secure bool
					if err = connection.QueryRow(ctx, "SELECT current_user, ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()").Scan(&user, &secure); err != nil {
						return err
					}
					if user != "tnl_client" || !secure {
						return errors.New("incorrect target authentication or TLS")
					}
					return nil
				}
				configuration := mysql.NewConfig()
				configuration.User, configuration.Passwd, configuration.DBName, configuration.Net, configuration.Addr = "tnl_client", "testpass", "tnl_fixture", "tcp", address
				configuration.Timeout, configuration.ReadTimeout, configuration.WriteTimeout = 5*time.Second, 5*time.Second, 5*time.Second
				configuration.TLSConfig = "false"
				if verification != nil {
					key := "tnl-managed-native"
					if err := mysql.RegisterTLSConfig(key, verification); err != nil {
						return err
					}
					defer mysql.DeregisterTLSConfig(key)
					configuration.TLSConfig = key
				}
				database, err := sql.Open("mysql", configuration.FormatDSN())
				if err != nil {
					return err
				}
				defer database.Close()
				database.SetMaxOpenConns(1)
				var user string
				if err = database.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&user); err != nil {
					return err
				}
				if !strings.HasPrefix(user, "tnl_client@") {
					return errors.New("incorrect target user")
				}
				var name, cipher string
				if err = database.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Ssl_cipher'").Scan(&name, &cipher); err != nil {
					return err
				}
				if cipher == "" {
					return errors.New("target connection is not TLS")
				}
				return nil
			}
			t.Run("native-TLS-and-mTLS", func(t *testing.T) {
				if err := query(managedPublisherListener(t, server), clientTLS); err != nil {
					t.Fatal(err)
				}
			})
			t.Run("trusted-destination-port-before-native-negotiation", func(t *testing.T) {
				if err := query(managedIngressListener(t, server), clientTLS); err != nil {
					t.Fatal(err)
				}
			})
			t.Run("connector-native-TLS-without-client-certificate", func(t *testing.T) {
				private := server
				private.Visitor = publisher.ConnectorVisitor{Check: func(context.Context) (publisher.ManagedVisitorDecision, error) {
					return publisher.ManagedVisitorDecision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
				}}
				front := clientTLS.Clone()
				front.Certificates = nil
				front.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					t.Error("connector admission requested another client credential")
					return nil, publisher.ErrManagedTLS
				}
				if err := query(managedPublisherListener(t, private), front); err != nil {
					t.Fatal(err)
				}
			})
			for _, name := range []string{"no-native-TLS", "no-client-certificate", "wrong-service-name", "wrong-target-name", "wrong-target-CA", "no-target-TLS"} {
				t.Run(name, func(t *testing.T) {
					front := clientTLS.Clone()
					back := server
					back.TargetTLS = server.TargetTLS.Clone()
					switch name {
					case "no-native-TLS":
						front = nil
					case "no-client-certificate":
						front.Certificates = nil
					case "wrong-service-name":
						front.ServerName = "sibling.production.storefront.example.test"
					case "wrong-target-name":
						back.TargetTLS.ServerName = "other.target.example.test"
					case "wrong-target-CA":
						back.TargetTLS.RootCAs = certificates.roots
					case "no-target-TLS":
						back.TargetTLS = nil
					}
					if err := query(managedPublisherListener(t, back), front); err == nil {
						t.Fatal("invalid TLS boundary authenticated a database client")
					}
				})
			}
		})
	}
	if !selected {
		t.Fatal("select a disposable TLS database provider")
	}
}

func runNativeDatabaseCommand(t *testing.T, protocol config.ProtocolName, container, address string, certificates managedTLSFixture, direct bool) {
	t.Helper()
	if container == "" {
		t.Fatal("native database command requires the Task-managed provider container")
	}
	key, err := x509.MarshalPKCS8PrivateKey(certificates.client.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	for name, data := range map[string][]byte{"ca.pem": certificates.ca, "client.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificates.client.Certificate[0]}), "client.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.CommandContext(t.Context(), "docker", "cp", path, container+":/tnl-fixture/"+name).CombinedOutput(); err != nil {
			t.Fatalf("copy native client fixture: %v %s", err, output)
		}
	}
	_, port, _ := net.SplitHostPort(address)
	host := "orders.production.storefront.example.test"
	client := "psql"
	if protocol == config.ProtocolMySQL {
		client = "mysql"
	}
	version, err := exec.CommandContext(t.Context(), "docker", "exec", container, client, "--version").CombinedOutput()
	if err != nil {
		t.Fatal("native client version", err)
	}
	t.Log(strings.TrimSpace(string(version)))
	args := []string{"exec", "-e", "SSL_CERT_FILE=/tnl-fixture/ca.pem", "-e", "PGPASSWORD=testpass", container}
	if protocol == config.ProtocolPostgres {
		query := url.Values{"sslmode": {"verify-full"}, "sslrootcert": {"system"}, "channel_binding": {"disable"}, "gssencmode": {"disable"}}
		if direct {
			query.Set("sslcert", "/tnl-fixture/client.pem")
			query.Set("sslkey", "/tnl-fixture/client.key")
		}
		endpoint := url.URL{Scheme: "postgresql", User: url.User("tnl_client"), Host: net.JoinHostPort(host, port), Path: "/tnl_fixture", RawQuery: query.Encode()}
		args = append(args, "psql", endpoint.String(), "-X", "-A", "-t", "-c", "SELECT current_user, ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()")
	} else {
		args = append(args, "mysql", "--host="+host, "--port="+port, "--ssl-mode=VERIFY_IDENTITY", "--ssl-ca=/tnl-fixture/ca.pem")
		if direct {
			args = append(args, "--ssl-cert=/tnl-fixture/client.pem", "--ssl-key=/tnl-fixture/client.key")
		}
		args = append(args, "--user=tnl_client", "--password=testpass", "--batch", "--skip-column-names", "--execute=SELECT CURRENT_USER(); SHOW SESSION STATUS LIKE 'Ssl_cipher';", "tnl_fixture")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil || !strings.Contains(string(output), "tnl_client") {
		t.Fatalf("native %s command: %v\n%s", protocol, err, output)
	}
	if protocol == config.ProtocolPostgres && !strings.Contains(string(output), "|t") {
		t.Fatal("native psql did not reach TLS target", string(output))
	}
}
