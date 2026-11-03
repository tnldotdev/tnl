package publisher_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/project/meta"
	"github.com/tnldotdev/tnl/internal/config"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/testutil"
)

// a prepared SDK connection runs one query against the disposable TLS provider.
// target certificate rejection is checked separately by the provider integration test.
func TestIntegrationDatabaseSDKSmoke(t *testing.T) {
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
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(root, "tnl")
			build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./cmd/tnl")
			build.Dir = "../.."
			if output, err := build.CombinedOutput(); err != nil {
				t.Fatalf("build native binary: %v %s", err, output)
			}
			ca, err := os.ReadFile(*setting.ca)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(ca) {
				t.Fatal("invalid disposable target CA")
			}
			certificates := serviceCertificates(t)
			const hostname = "orders.production.storefront.example.test"
			deadline := time.Now().Add(4 * time.Minute)
			server := publisher.ServiceStream{Protocol: setting.protocol, Hostname: hostname, Target: *setting.address,
				TLS:       &tls.Config{Certificates: []tls.Certificate{certificates.server}, MinVersion: tls.VersionTLS12},
				TargetTLS: &tls.Config{RootCAs: roots, ServerName: *setting.hostname, MinVersion: tls.VersionTLS12},
				Visitor: publisher.ConnectorVisitor{Admission: publisher.NativeAdmissionFixture{Check: func(context.Context) (publisher.ServiceVisitorDecision, error) {
					return publisher.ServiceVisitorDecision{Allowed: true, ValidUntil: deadline}, nil
				}}},
			}
			address := managedIngressListener(t, server, func() publisher.ServiceVisitorAuthentication { return server.Visitor })
			_, port, _ := net.SplitHostPort(address)
			number, _ := strconv.Atoi(port)
			backend := &databaseSmokeBackend{
				deadline: deadline,
				metadata: meta.PublicMetadata{Namespace: "production.storefront.example.test", Services: map[string]meta.Service{
					"database": {Protocol: string(setting.protocol), Namespace: "production.storefront.example.test", Hostname: hostname, Port: number},
				}},
				connections: map[string]connectorruntime.Connection{
					"database": {Schema: 1, Protocol: string(setting.protocol), Host: "127.0.0.1", Port: number, ExpiresAt: deadline, TransportID: "ctg_aaaaaaaaaaaaaaaaaaaaaa",
						SSL: &connectorruntime.TLSOptions{ServerName: hostname, RejectUnauthorized: true, CA: string(certificates.ca)}},
				},
			}
			directory, err := connectorruntime.NewDirectory(root)
			if err != nil {
				t.Fatal(err)
			}
			scope := connectorruntime.Context{Schema: 1, Directory: root, ConfigDigest: strings.Repeat("a", 64), Server: "https://control.example.test", Audience: "https://control.example.test", ProjectKey: "driver-fixture", SourceID: "fixture", WorktreeKey: "fixture", Services: []string{"database"}}
			reader, writer := io.Pipe()
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() {
				done <- connectorruntime.Serve(ctx, scope, directory, binary, backend, writer)
				_ = writer.Close()
			}()
			defer func() {
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			var state connectorruntime.Status
			if err := json.NewDecoder(reader).Decode(&state); err != nil {
				t.Fatal(err)
			}
			_ = reader.Close()
			fixture, err := filepath.Abs("../../packages/ts/test/fixtures/connections/database-smoke.ts")
			if err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(t.Context(), "node", fixture, string(setting.protocol))
			command.Dir = root
			for _, value := range os.Environ() {
				if !strings.HasPrefix(value, "TNL_") && !strings.HasPrefix(value, "NODE_OPTIONS=") {
					command.Env = append(command.Env, value)
				}
			}
			command.Env = append(command.Env, "TNL_CONNECTION_HANDLE="+state.ConnectionHandle)
			if err := command.Run(); err != nil {
				t.Fatalf("database SDK smoke (%s): %v", setting.protocol, err)
			}
		})
	}
	if !selected {
		t.Fatal("select a disposable TLS database provider")
	}
}

type databaseSmokeBackend struct {
	deadline    time.Time
	metadata    meta.PublicMetadata
	connections map[string]connectorruntime.Connection
}

func (b *databaseSmokeBackend) Start(context.Context) (meta.PublicMetadata, time.Time, error) {
	return b.metadata, b.deadline, nil
}
func (b *databaseSmokeBackend) Prepared(name string) (connectorruntime.Connection, error) {
	return b.Connect(context.Background(), name)
}
func (b *databaseSmokeBackend) Connect(_ context.Context, name string) (connectorruntime.Connection, error) {
	connection, ok := b.connections[name]
	if !ok {
		return connectorruntime.Connection{}, connectorruntime.ErrUnauthorized
	}
	return connection, nil
}
func (b *databaseSmokeBackend) Renew(context.Context) (time.Time, error) { return b.deadline, nil }
func (b *databaseSmokeBackend) Close(context.Context) error              { return nil }
