package main

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	nativeauth "github.com/tnldotdev/tnl/internal/publisher/identity"
	privatepublisher "github.com/tnldotdev/tnl/internal/publisher/managed"
	privatetrust "github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationCLIConnectMetadataReload(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if runtime.GOOS != "linux" {
		t.Skip("real CLI credential protection requires Linux")
	}
	if !*cliWorkflowChild {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(t.Context(), executable, "-test.run=^TestIntegrationCLIConnectMetadataReload$", "-test.v", "-test.timeout=3m", "-tnl-test-tier=integration",
			"-tnl-test-postgres-url="+flag.Lookup("tnl-test-postgres-url").Value.String(), "-tnl-cli-workflow-child")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("connector reload CLI: %v\n%s", err, output)
		}
		t.Logf("%s", output)
		return
	}
	f := newCLIWorkflow(t)
	for _, detached := range []bool{false, true} {
		t.Run(fmt.Sprintf("detached=%t", detached), func(t *testing.T) {
			person := f.state(t, "visitor")
			f.loginPerson(t, person)
			session, err := openTeamSession(t.Context(), remoteFlags{ServerURL: f.url, StateDir: person}, "connector reload", io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			target := workflowListen(t)
			var targetTLS atomic.Bool
			targetTLS.Store(true)
			f.serve(t, target, func(conn net.Conn) error {
				stop := context.AfterFunc(f.ctx, func() { _ = conn.Close() })
				defer stop()
				if targetTLS.Load() {
					conn = tls.Server(conn, f.tls)
				}
				_, err := io.Copy(conn, conn)
				return err
			})
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.issuer.Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			hostname := "localhost"
			trust, err := privatetrust.NewCache(nil).Capture(t.Context(), root, target.Addr().String(), config.TrustSource{Hostname: &hostname, CA: "ca.pem"})
			if err != nil {
				t.Fatal(err)
			}
			key, _ := randomIdempotencyKey()
			service, err := session.Authenticated().Control.CreatePrivateService(t.Context(), session.Identity().PersonalTeamId, fmt.Sprintf("reload-%t", detached), key,
				controlv1.PrivateServiceMetadata{Protocol: "tcp", TrustRevision: 1, TargetTls: nativeauth.PrivateServiceTLS(&trust)})
			if err != nil {
				t.Fatal(err)
			}
			native, identity, err := nativeauth.EnsurePrivateServiceOwner(t.Context(), session.Store(), session.Authenticated().Control, session.Authenticated().Authority, service)
			if err != nil {
				t.Fatal(err)
			}
			startPublisher := func(service controlv1.PrivateService) func() {
				t.Helper()
				ctx, cancel := context.WithCancel(t.Context())
				ready, done := make(chan struct{}), make(chan error, 1)
				go func() {
					done <- privatepublisher.Publish(ctx, privatepublisher.RunConfig{Control: session.Authenticated().Control, Access: native.Access, Identity: identity,
						State: session.Store(), PrivateServiceID: service.Id, Target: target.Addr().String(), Metadata: nativeauth.PrivateServiceMetadata(service),
						HeartbeatInterval: 100 * time.Millisecond, Ready: func() error { close(ready); return nil }})
				}()
				stop := sync.OnceFunc(func() {
					cancel()
					select {
					case <-done:
					case <-time.After(10 * time.Second):
						t.Error("publisher did not join")
					}
				})
				t.Cleanup(stop)
				select {
				case <-ready:
				case err := <-done:
					done <- err
					t.Fatalf("publisher startup: %v", err)
				case <-time.After(15 * time.Second):
					t.Fatal("publisher not ready")
				}
				return stop
			}
			stopPublisher := startPublisher(service)
			listener := workflowListen(t)
			address := listener.Addr().String()
			_ = listener.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			args := []string{"--no-config", "--no-telemetry", "connect", service.Id, "--listen", address, "--server", f.url, "--state-dir", person}
			const detachedID = "abcdef0123456789abcdef02"
			if detached {
				args = append(args, "--detached-child="+detachedID)
			}
			ready, done := make(chan struct{}, 8), make(chan error, 1)
			go func() {
				done <- run(ctx, args, io.Discard, workflowLifecycleLog{t: t, ready: func() { ready <- struct{}{} }})
			}()
			joined := false
			defer func() {
				cancel()
				if !joined {
					select {
					case <-done:
					case <-time.After(10 * time.Second):
						t.Error("CLI did not join")
					}
				}
			}()
			waitReady := func() {
				t.Helper()
				select {
				case <-ready:
				case err := <-done:
					done <- err
					t.Fatalf("connector stopped: %v", err)
				case <-time.After(15 * time.Second):
					t.Fatal("connector not ready")
				}
				if detached {
					workflowWait(t, time.Second, func() bool {
						status, err := detachedRequest(person, detachedID, "status")
						return err == nil && status == fmt.Sprintf("ready %d", os.Getpid())
					})
				}
			}
			waitReady()
			open := func() net.Conn {
				t.Helper()
				conn, err := net.DialTimeout("tcp", address, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.WriteString(conn, "private-login"); err != nil {
					t.Fatal(err)
				}
				data := make([]byte, len("private-login"))
				if _, err := io.ReadFull(conn, data); err != nil || string(data) != "private-login" {
					t.Fatalf("fresh approved TLS did not carry bytes: %v", err)
				}
				return conn
			}
			old := open()
			defer func() { _ = old.Close() }()
			for _, enabled := range []bool{false, true} {
				metadata := nativeauth.PrivateServiceMetadata(service)
				metadata.TargetTls = nil
				if enabled {
					metadata.TargetTls = nativeauth.PrivateServiceTLS(&trust)
				}
				service, err = session.Authenticated().Control.ConfigurePrivateService(t.Context(), service.Id, metadata)
				if err != nil {
					t.Fatal(err)
				}
				previousPublisher := stopPublisher
				targetTLS.Store(enabled)
				stopPublisher = startPublisher(service)
				// this fresh local connection observes the changed revision and ends
				// the old runner. no bytes from it may reach the target.
				trigger, err := net.Dial("tcp", address)
				if err != nil {
					t.Fatal(err)
				}
				_ = trigger.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, err := trigger.Read(make([]byte, 1)); err == nil {
					t.Fatal("metadata trigger forwarded bytes")
				}
				_ = trigger.Close()
				waitReady()
				previousPublisher()
				_ = old.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := old.Read(make([]byte, 1)); err == nil {
					t.Fatal("old stream survived metadata reload")
				} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					t.Fatal("old stream was not closed")
				}
				_ = old.Close()
				old = open()
			}
			// revoke access after the runner detects a new revision, before the
			// outer lifecycle reads inventory. a same-name record cannot replace it.
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			hook := func() { once.Do(func() { close(entered); <-release }) }
			f.beforeVisitorInventory.Store(&hook)
			defer f.beforeVisitorInventory.Store(nil)
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			metadata := nativeauth.PrivateServiceMetadata(service)
			metadata.TargetTls = nil
			service, err = session.Authenticated().Control.ConfigurePrivateService(t.Context(), service.Id, metadata)
			if err != nil {
				t.Fatal(err)
			}
			previousPublisher := stopPublisher
			defer previousPublisher()
			targetTLS.Store(false)
			stopPublisher = startPublisher(service)
			defer stopPublisher()
			trigger, err := net.Dial("tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			defer trigger.Close()
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("reload did not refetch visitor inventory")
			}
			if detached {
				status, err := detachedRequest(person, detachedID, "status")
				if err != nil || status != fmt.Sprintf("starting %d", os.Getpid()) {
					t.Fatalf("reload did not clear readiness: %q %v", status, err)
				}
			}
			database, err := controlstate.Open(t.Context(), f.databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			grants, _, err := database.ListPrivateServiceGrants(t.Context(), service.Id, session.Identity().Identity.Id, "")
			if err != nil {
				t.Fatal(err)
			}
			for _, grant := range grants {
				if err := database.RevokePrivateServiceGrant(t.Context(), service.Id, session.Identity().Identity.Id, grant.ID, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			unblock()
			select {
			case err := <-done:
				joined = true
				if err == nil {
					t.Fatal("revoked refresh succeeded")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("revoked connector did not stop")
			}
			select {
			case <-ready:
				t.Fatal("revoked metadata emitted readiness")
			default:
			}
			if conn, err := net.DialTimeout("tcp", address, time.Second); err == nil {
				_ = conn.Close()
				t.Fatal("revoked refresh reopened reserved listener")
			}
		})
	}
}
