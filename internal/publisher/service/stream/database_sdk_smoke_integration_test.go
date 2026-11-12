package stream_test

import (
	"bufio"
	"bytes"
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

	"github.com/tnldotdev/tnl/internal/client/project/meta"
	"github.com/tnldotdev/tnl/internal/config"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"

	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
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
			build.Dir = "../../../.."
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
			server := servicestream.Stream{Protocol: setting.protocol, Hostname: hostname, Target: *setting.address,
				TLS:       &tls.Config{Certificates: []tls.Certificate{certificates.server}, MinVersion: tls.VersionTLS12},
				TargetTLS: &tls.Config{RootCAs: roots, ServerName: *setting.hostname, MinVersion: tls.VersionTLS12},
				Visitor: servicestream.ConnectorVisitor{Admission: servicestream.AdmissionFixture{Check: func(context.Context) (servicestream.Decision, error) {
					return servicestream.Decision{Allowed: true, ValidUntil: deadline}, nil
				}}},
			}
			address := managedIngressListener(t, server, func() servicestream.Authentication { return server.Visitor })
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
				done <- connectorruntime.Serve(ctx, scope, directory, binary, connectorruntime.OwnerConfig{Backend: backend}, writer)
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
			for _, language := range []string{"javascript", "python"} {
				if language == "python" && setting.protocol != config.ProtocolPostgres {
					continue
				}
				t.Run(language, func(t *testing.T) {
					runDatabaseSDKSmoke(t, root, binary, state, backend, string(setting.protocol), language)
				})
			}
		})
	}
	if !selected {
		t.Fatal("select a disposable TLS database provider")
	}
}

type databaseSmokeBackend struct {
	mu          sync.RWMutex
	transport   string
	deadline    time.Time
	metadata    meta.PublicMetadata
	connections map[string]connectorruntime.Connection
}

func (b *databaseSmokeBackend) Start(context.Context) (meta.PublicMetadata, time.Time, error) {
	return b.metadata, b.deadline, nil
}
func (*databaseSmokeBackend) UseAssertion(context.Context, string) error {
	return connectorruntime.ErrInvalid
}
func (*databaseSmokeBackend) Attach(context.Context, string) error {
	return connectorruntime.ErrInvalid
}
func (b *databaseSmokeBackend) ProjectRuntime() meta.PublicMetadata { return b.metadata }
func (b *databaseSmokeBackend) SnapshotFor(name, assertion string) (connectorruntime.Prepared, error) {
	if assertion != "" {
		return connectorruntime.Prepared{}, connectorruntime.ErrInvalid
	}
	connection, err := b.Prepared(name)
	return connectorruntime.Prepared{Schema: 1, ProjectRuntime: b.metadata, Connection: connection}, err
}
func (b *databaseSmokeBackend) Prepared(name string) (connectorruntime.Connection, error) {
	return b.Connect(context.Background(), name)
}
func (b *databaseSmokeBackend) Connect(_ context.Context, name string) (connectorruntime.Connection, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	connection, ok := b.connections[name]
	if !ok {
		return connectorruntime.Connection{}, connectorruntime.ErrUnauthorized
	}
	if b.transport != "" {
		connection.TransportID = "ctg_" + strings.Repeat(b.transport, 22)
	}
	// every read has a new permission deadline without changing its binding.
	connection.ExpiresAt = minTimeForDatabaseSmoke(b.deadline, time.Now().Add(time.Minute))
	return connection, nil
}
func (b *databaseSmokeBackend) Renew(context.Context) (time.Time, error) { return b.deadline, nil }
func (b *databaseSmokeBackend) Close(context.Context) error              { return nil }

func minTimeForDatabaseSmoke(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func runDatabaseSDKSmoke(t *testing.T, root, binary string, state connectorruntime.Status, backend *databaseSmokeBackend, protocol, language string) {
	t.Helper()
	backend.mu.Lock()
	backend.transport = "a"
	backend.mu.Unlock()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	fixture, err := filepath.Abs("../../../../packages/ts/test/fixtures/connections/database-smoke.ts")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "node", fixture, protocol)
	if language == "python" {
		python, err := filepath.Abs("../../../../packages/py/.venv/bin/python")
		if err != nil {
			t.Fatal(err)
		}
		fixture, err = filepath.Abs("../../../../packages/py/tests/database_smoke.py")
		if err != nil {
			t.Fatal(err)
		}
		command = exec.CommandContext(ctx, python, fixture, binary)
	}
	command.Dir = root
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "TNL_") && !strings.HasPrefix(value, "NODE_OPTIONS=") {
			command.Env = append(command.Env, value)
		}
	}
	command.Env = append(command.Env, "TNL_CONNECTION_HANDLE="+state.ConnectionHandle)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		cancel()
		if !waited {
			_ = command.Wait()
		}
	}()
	scanner := bufio.NewScanner(output)
	for _, step := range []struct{ event, transport string }{{"binding-a", "b"}, {"binding-b", "a"}, {"closed", ""}} {
		if !scanner.Scan() || scanner.Text() != step.event {
			cancel()
			err := command.Wait()
			waited = true
			t.Fatalf("database SDK %s: wanted %s, got %q: %v; %v\n%s", language, step.event, scanner.Text(), scanner.Err(), err, stderr.String())
		}
		if step.transport == "" {
			break
		}
		backend.mu.Lock()
		backend.transport = step.transport
		backend.mu.Unlock()
		if _, err := io.WriteString(input, "next\n"); err != nil {
			t.Fatal(err)
		}
	}
	err = command.Wait()
	waited = true
	if err != nil {
		t.Fatalf("database SDK %s: %v\n%s", language, err, stderr.String())
	}
	handle, err := connectorruntime.ReadHandle(state.ConnectionHandle)
	if err != nil {
		t.Fatal("factory cleanup stopped the shared native owner", err)
	}
	var current connectorruntime.Status
	if err := connectorruntime.Call(t.Context(), state.ConnectionHandle, "status", connectorruntime.Request{Schema: 1, Directory: handle.Directory, ConfigDigest: handle.ConfigDigest}, &current); err != nil || current.PID != state.PID {
		t.Fatal("factory cleanup replaced the shared native owner", err)
	}
	t.Log("real database pools retained original connections across changing permission deadlines and A/B/A bindings; joined driver cleanup left the native owner running")
}
