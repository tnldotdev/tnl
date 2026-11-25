package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/background"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connector"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationCLIConnectMetadataReload(t *testing.T) {
	if !cliWorkflowInChild(t) {
		return
	}
	f := newCLIWorkflow(t)
	command := workflowBackgroundCLI(t, f)
	for _, mode := range []string{"foreground", "background"} {
		t.Run(mode, func(t *testing.T) {
			bg := mode == "background"
			person := f.state(t, "visitor")
			if bg {
				t.Cleanup(func() { cleanupBackgroundJobs(t, person) })
			}
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
			trust, err := targettrust.NewCache(nil).Capture(t.Context(), root, target.Addr().String(), config.TrustSource{Hostname: &hostname, CA: "ca.pem"})
			if err != nil {
				t.Fatal(err)
			}
			key, _ := randomIdempotencyKey()
			service, err := session.Authenticated().Control.CreateService(t.Context(), session.Identity().PersonalTeamId, "reload-"+mode, key,
				controlv1.ServiceMetadata{Protocol: "tcp", TrustRevision: 1, TargetTls: publisheridentity.ServiceTargetTLS(&trust)}, nil)
			if err != nil {
				t.Fatal(err)
			}
			native, identity, err := publisheridentity.EnsureServiceOwner(t.Context(), session.Store(), session.Authenticated().Control, session.Authenticated().Authority, service)
			if err != nil {
				t.Fatal(err)
			}
			startPublisher := func(service controlv1.Service) func() {
				t.Helper()
				ctx, cancel := context.WithCancel(t.Context())
				ready, done := make(chan struct{}), make(chan error, 1)
				go func() {
					done <- publisherservice.Publish(ctx, publisherservice.RunConfig{Control: native, Access: native.Access,
						PublisherIdentityID: identity.ClientId, PublisherGrantID: identity.GrantId, PublisherKeyID: identity.KeyId,
						State: session.Store(), ServiceID: service.Id, Target: target.Addr().String(), Metadata: publisheridentity.ServiceMetadata(service),
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
			args := []string{"connect", service.Id, "--listen", address, "--server", f.url, "--state-dir", person}
			var ready chan struct{}
			var done chan error
			var launched chan workflowCLIResult
			var cancel context.CancelFunc
			var jobID string
			startConnector := func() {
				t.Helper()
				if done != nil || launched != nil {
					t.Fatal("previous connector invocation was not joined")
				}
				ctx, stop := context.WithCancel(t.Context())
				cancel = stop
				if bg {
					launched = make(chan workflowCLIResult, 1)
					go func(result chan<- workflowCLIResult) {
						result <- command(ctx, append(args, "--bg", "--output=json")...)
					}(launched)
					return
				}
				ready, done = make(chan struct{}, 8), make(chan error, 1)
				go func(ready chan<- struct{}, done chan<- error) {
					log := workflowLifecycleLog{t: t, ready: func() { ready <- struct{}{} }}
					done <- log.run(ctx, append([]string{"--no-config", "--no-telemetry"}, args...))
				}(ready, done)
			}
			defer func() {
				if cancel != nil {
					cancel()
				}
				if done != nil {
					select {
					case <-done:
					case <-time.After(10 * time.Second):
						t.Error("CLI did not join")
					}
				}
				if launched != nil {
					select {
					case <-launched:
					case <-time.After(10 * time.Second):
						t.Error("background launcher did not join")
					}
				}
			}()
			waitLaunch := func() workflowCLIResult {
				t.Helper()
				select {
				case result := <-launched:
					launched = nil
					cancel()
					return result
				case <-time.After(35 * time.Second):
					t.Fatal("background launch did not return")
					return workflowCLIResult{}
				}
			}
			joinReplacedConnector := func() {
				t.Helper()
				if bg {
					waitBackgroundJobExit(t, t.Context(), person, jobID)
				} else {
					select {
					case err := <-done:
						done = nil
						cancel()
						if !errors.Is(err, connectorstream.ErrServiceConnection) && !errors.Is(err, clientcontrol.ErrNotFound) {
							t.Fatalf("replaced connector did not stop with an obsolete run: %v", err)
						}
					case <-time.After(10 * time.Second):
						t.Fatal("replaced connector did not join")
					}
				}
				if conn, err := net.DialTimeout("tcp", address, time.Second); err == nil {
					_ = conn.Close()
					t.Fatal("old connector listener survived publisher replacement")
				}
			}
			waitReady := func() {
				t.Helper()
				if bg {
					result := waitLaunch()
					var receipt connector.Profile
					host, port, _ := net.SplitHostPort(address)
					if err := json.Unmarshal(result.stdout, &receipt); result.err != nil || len(result.stderr) != 0 || err != nil ||
						receipt.Schema != 1 || receipt.Protocol != config.ProtocolTCP || receipt.ServiceID != service.Id ||
						!receipt.ConnectorRequired || receipt.Host != host || strconv.Itoa(receipt.Port) != port ||
						!opaqueid.Valid(receipt.JobID, opaqueid.JobPrefix) || receipt.JobID == jobID {
						t.Fatalf("invalid background connector receipt: %s (%v %v)\n%s", result.stdout, result.err, err, result.stderr)
					}
					jobID = receipt.JobID
					job, err := background.Status(t.Context(), person, jobID)
					if err != nil || job.State != background.StateReady || job.Kind != background.KindConnect ||
						job.Address != address || job.PID == os.Getpid() {
						t.Fatalf("receipt does not identify the ready connector on %s: %+v (%v)", address, job, err)
					}
					return
				}
				select {
				case <-ready:
				case err := <-done:
					done = nil
					t.Fatalf("connector stopped: %v", err)
				case <-time.After(15 * time.Second):
					t.Fatal("connector not ready")
				}
			}
			startConnector()
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
				metadata := publisheridentity.ServiceMetadata(service)
				metadata.TargetTls = nil
				if enabled {
					metadata.TargetTls = publisheridentity.ServiceTargetTLS(&trust)
				}
				service, err = session.Authenticated().Control.ConfigureService(t.Context(), service.Id, controlv1.UpdateServiceRequest{Protocol: metadata.Protocol, TargetTls: metadata.TargetTls, PublisherPool: metadata.PublisherPool, ExpectedTrustRevision: service.TrustRevision})
				if err != nil {
					t.Fatal(err)
				}
				previousPublisher := stopPublisher
				targetTLS.Store(enabled)
				stopPublisher = startPublisher(service)
				// publisher replacement ends the old invocation. a fresh invocation
				// must authorize current metadata without reusing its old peer.
				joinReplacedConnector()
				previousPublisher()
				_ = old.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := old.Read(make([]byte, 1)); err == nil {
					t.Fatal("old stream survived metadata reload")
				} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					t.Fatal("old stream was not closed")
				}
				_ = old.Close()
				startConnector()
				waitReady()
				old = open()
			}
			// revoke access while the next invocation reads current inventory.
			// neither cached metadata nor a same-name record can authorize it.
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			hook := func() { once.Do(func() { close(entered); <-release }) }
			f.beforeVisitorInventory.Store(&hook)
			defer f.beforeVisitorInventory.Store(nil)
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			metadata := publisheridentity.ServiceMetadata(service)
			metadata.TargetTls = nil
			service, err = session.Authenticated().Control.ConfigureService(t.Context(), service.Id, controlv1.UpdateServiceRequest{Protocol: metadata.Protocol, TargetTls: metadata.TargetTls, PublisherPool: metadata.PublisherPool, ExpectedTrustRevision: service.TrustRevision})
			if err != nil {
				t.Fatal(err)
			}
			previousPublisher := stopPublisher
			defer previousPublisher()
			targetTLS.Store(false)
			stopPublisher = startPublisher(service)
			defer stopPublisher()
			joinReplacedConnector()
			previousPublisher()
			startConnector()
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("new invocation did not refetch visitor inventory")
			}
			var pendingID string
			if bg {
				jobs, err := background.List(t.Context(), person)
				if err != nil || len(jobs) != 1 || jobs[0].Kind != background.KindConnect ||
					jobs[0].State != background.StateStarting || jobs[0].JobID == jobID || jobs[0].Address != "" {
					t.Fatalf("pending authorization advertised readiness or lost its owner: %+v (%v)", jobs, err)
				}
				pendingID = jobs[0].JobID
			}
			database, err := controlstate.Open(t.Context(), f.databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeGenerated)
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			grants, _, err := database.ListServiceGrants(t.Context(), service.Id, session.Identity().Identity.Id, "")
			if err != nil {
				t.Fatal(err)
			}
			for _, grant := range grants {
				if err := database.RevokeServiceGrant(t.Context(), service.Id, session.Identity().Identity.Id, grant.ID, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			unblock()
			if bg {
				result := waitLaunch()
				var problem struct {
					Type string         `json:"type"`
					Code failure.Reason `json:"code"`
				}
				var exit *exec.ExitError
				if !errors.As(result.err, &exit) || exit.ExitCode() != 1 || len(result.stdout) != 0 ||
					json.Unmarshal(result.stderr, &problem) != nil || problem.Type != "error" || problem.Code != failure.ServerResourceNotFound {
					t.Fatalf("revoked background invocation emitted a receipt or missed its startup failure: %s (%v)\n%s", result.stdout, result.err, result.stderr)
				}
				waitBackgroundJobExit(t, t.Context(), person, pendingID)
			} else {
				select {
				case err := <-done:
					done = nil
					if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResourceNotFound {
						t.Fatalf("revoked invocation did not fail inventory authorization: %v", err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("revoked connector did not stop")
				}
				select {
				case <-ready:
					t.Fatal("revoked metadata emitted readiness")
				default:
				}
			}
			if conn, err := net.DialTimeout("tcp", address, time.Second); err == nil {
				_ = conn.Close()
				t.Fatal("revoked refresh reopened reserved listener")
			}
		})
	}
}
