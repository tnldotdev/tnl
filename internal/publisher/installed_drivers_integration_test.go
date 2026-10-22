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
	"sync"
	"testing"
	"time"

	projectmeta "github.com/tnldotdev/tnl/internal/client/project/meta"
	"github.com/tnldotdev/tnl/internal/config"
	connectionruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/testutil"
)

// the real owner serves prepared IPC to the installed native binary. ingress and
// publisher negotiate both TLS legs with the real Docker-owned database. policy
// and placement are fixture decisions; this tier does not exercise authority.
func TestIntegrationInstalledDatabaseDrivers(t *testing.T) {
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
				t.Fatalf("build installed native binary: %v %s", err, output)
			}
			ca, err := os.ReadFile(*setting.ca)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(ca) {
				t.Fatal("invalid disposable target CA")
			}
			certificates := managedCertificates(t)
			backend := &installedDriverBackend{deadline: time.Now().Add(4 * time.Minute), metadata: projectmeta.PublicMetadata{Namespace: "production.storefront.example.test", Services: map[string]projectmeta.Service{}}, connections: map[string]connectionruntime.Connection{}}
			for _, name := range []string{"database", "wrong-name", "expiring", "renewing"} {
				hostname := "orders.production.storefront.example.test"
				certificate := certificates.server
				if name == "wrong-name" {
					hostname = "other.production.storefront.example.test"
					certificate = certificates.wrongName
				} else if name != "database" {
					hostname = name + ".production.storefront.example.test"
				}
				check := func(context.Context) (publisher.ManagedVisitorDecision, error) {
					return publisher.ManagedVisitorDecision{Allowed: true, ValidUntil: backend.deadline}, nil
				}
				server := publisher.ManagedStream{Protocol: setting.protocol, Hostname: hostname, Target: *setting.address,
					TLS:       &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
					TargetTLS: &tls.Config{RootCAs: roots, ServerName: *setting.hostname, MinVersion: tls.VersionTLS12},
					Visitor:   publisher.ConnectorVisitor{Check: check}}
				address := managedIngressListener(t, server, func() publisher.ManagedVisitorAuthentication {
					if name == "expiring" || name == "renewing" {
						// each stream keeps its originally selected connector decision.
						lifetime := &installedDriverLifetime{renew: name == "renewing"}
						return publisher.ConnectorVisitor{Check: lifetime.check}
					}
					return server.Visitor
				})
				_, port, _ := net.SplitHostPort(address)
				number, _ := strconv.Atoi(port)
				backend.metadata.Services[name] = projectmeta.Service{Protocol: string(setting.protocol), Namespace: backend.metadata.Namespace, Hostname: hostname, Port: number}
				backend.connections[name] = connectionruntime.Connection{Schema: 1, Protocol: string(setting.protocol), Host: "127.0.0.1", Port: number, ExpiresAt: backend.deadline, SSL: &connectionruntime.TLSOptions{ServerName: hostname, RejectUnauthorized: true, CA: string(certificates.ca)}}
			}
			directory, err := connectionruntime.NewDirectory(root)
			if err != nil {
				t.Fatal(err)
			}
			scope := connectionruntime.Context{Schema: 1, Directory: root, ConfigDigest: strings.Repeat("a", 64), Server: "https://control.example.test", Audience: "https://control.example.test", ProjectKey: "driver-fixture", SourceID: "fixture", WorktreeKey: "fixture", Services: []string{"database", "wrong-name", "expiring", "renewing"}}
			reader, writer := io.Pipe()
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() {
				done <- connectionruntime.Serve(ctx, scope, directory, binary, backend, writer)
				_ = writer.Close()
			}()
			defer func() {
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			var state connectionruntime.Status
			if err := json.NewDecoder(reader).Decode(&state); err != nil {
				t.Fatal(err)
			}
			_ = reader.Close()
			fixture, err := filepath.Abs("../../packages/ts/test/fixtures/connections/installed-drizzle.ts")
			if err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(t.Context(), "node", fixture, binary, string(setting.protocol)+"-drivers")
			command.Dir = root
			for _, value := range os.Environ() {
				if !strings.HasPrefix(value, "TNL_") && !strings.HasPrefix(value, "NODE_OPTIONS=") {
					command.Env = append(command.Env, value)
				}
			}
			command.Env = append(command.Env, "TNL_CONNECTION_HANDLE="+state.PrivateHandle)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("installed database driver verification: %v\n%s", err, output)
			}
			t.Log(strings.TrimSpace(string(output)))
			if setting.protocol == config.ProtocolPostgres {
				runInstalledPsycopg(t, root, binary, state.PrivateHandle)
			}
		})
	}
	if !selected {
		t.Fatal("select a disposable TLS database provider")
	}
}

type installedDriverLifetime struct {
	mu       sync.Mutex
	deadline time.Time
	renew    bool
}

func (l *installedDriverLifetime) check(context.Context) (publisher.ManagedVisitorDecision, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.deadline.IsZero() || l.renew {
		l.deadline = time.Now().Add(1200 * time.Millisecond)
	}
	return publisher.ManagedVisitorDecision{Allowed: true, ValidUntil: l.deadline}, nil
}

type installedDriverBackend struct {
	deadline    time.Time
	metadata    projectmeta.PublicMetadata
	connections map[string]connectionruntime.Connection
}

func (b *installedDriverBackend) Start(context.Context) (projectmeta.PublicMetadata, time.Time, error) {
	return b.metadata, b.deadline, nil
}
func (b *installedDriverBackend) Prepared(name string) (connectionruntime.Connection, error) {
	return b.Connect(context.Background(), name)
}
func (b *installedDriverBackend) Connect(_ context.Context, name string) (connectionruntime.Connection, error) {
	connection, ok := b.connections[name]
	if !ok {
		return connectionruntime.Connection{}, connectionruntime.ErrUnauthorized
	}
	return connection, nil
}
func (b *installedDriverBackend) Renew(context.Context) (time.Time, error) { return b.deadline, nil }
func (b *installedDriverBackend) Close(context.Context) error              { return nil }
