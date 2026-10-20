package tnldruntime

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/privatepublisher"
	"github.com/tnldotdev/tnl/internal/privatetrust"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/internal/tcpconnect"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func startPrivateHTTPPublisher(t *testing.T, f *privateSeparatedFixture, service controlv1.PrivateService, target string, overrides ...privatepublisher.RunControl) {
	t.Helper()
	enrollment, err := f.identity.routes.CreatePublisherEnrollment(t.Context(), controlv1.CreatePublisherEnrollmentRequest{TeamId: service.TeamId, PrivateServiceId: &service.Id, Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled, Name: "private-http"})
	if err != nil {
		t.Fatal(err)
	}
	native, identity, err := nativeauth.EnrollNative(t.Context(), f.identity.state, f.identity.routes, f.identity.authority, enrollment.EnrollmentKey)
	if err != nil {
		t.Fatal(err)
	}
	quic, tcp := f.connectors()
	ctx, cancel := context.WithCancel(t.Context())
	ready, done := make(chan struct{}), make(chan error, 1)
	heartbeat := 100 * time.Millisecond
	if f.defaultTiming {
		heartbeat = 0
	}
	var control privatepublisher.RunControl = f.identity.routes
	if len(overrides) == 1 {
		control = overrides[0]
	}
	go func() {
		done <- privatepublisher.Publish(ctx, privatepublisher.RunConfig{Control: control, State: f.identity.state, Access: native.Access, Identity: identity, PrivateServiceID: service.Id, Target: target,
			Metadata: controlv1.PrivateServiceMetadata{Protocol: service.Protocol, TargetTls: service.TargetTls, TrustRevision: service.TrustRevision, PublisherPool: service.PublisherPool}, HeartbeatInterval: heartbeat,
			Ready: func() error { close(ready); return nil }, Connect: func(ctx context.Context, bound *privatepublisher.Bound, slot uint8) (privatepublisher.SlotSession, error) {
				return bound.ConnectSlotWithTransports(ctx, slot, false, quic, tcp)
			}})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("private HTTP publisher shutdown: %v", err)
			}
		case <-time.After(12 * time.Second):
			t.Error("private HTTP publisher did not join")
		}
	})
	select {
	case <-ready:
	case err := <-done:
		done <- err
		t.Fatalf("private HTTP publisher failed: %v", err)
	case <-time.After(12 * time.Second):
		t.Fatal("private HTTP publisher did not become ready")
	}
}

func TestIntegrationPrivateHTTPProductionControl(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, standalone := range []bool{false, true} {
		for _, managedTLS := range []bool{false, true} {
			t.Run(fmt.Sprintf("standalone=%t/tnl-tls=%t", standalone, managedTLS), func(t *testing.T) {
				f := newPrivateRuntimeFixture(t, standalone, nil)
				if !standalone {
					startSeparatedPrivateIngress(t, f, 0, "quic", nil)
					startSeparatedPrivateIngress(t, f, 1, "quic", nil)
				}
				ca := newTestCertificateAuthority(t)
				const hostname = "target.private.integration.test"
				var posts atomic.Int64
				target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if managedTLS && r.TLS == nil {
						t.Errorf("approved HTTPS Host was not used: %s", r.Host)
					}
					switch r.URL.Path {
					case "/once":
						posts.Add(1)
						_, _ = io.Copy(w, r.Body)
					case "/watch":
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = io.WriteString(w, "data: ready\n\n")
						w.(http.Flusher).Flush()
						<-r.Context().Done()
					case "/exec":
						connection, buffer, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						defer connection.Close()
						_, _ = io.WriteString(buffer, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n")
						_ = buffer.Flush()
						_, _ = io.Copy(connection, buffer)
					}
				}))
				target.TLS = privateRuntimeTLS(t, ca, hostname)
				target.Config.ErrorLog = log.New(io.Discard, "", 0)
				if managedTLS {
					target.StartTLS()
				} else {
					target.Start()
				}
				t.Cleanup(target.Close)
				directory := t.TempDir()
				if err := os.WriteFile(filepath.Join(directory, "ca.pem"), ca.certificatePEM, 0600); err != nil {
					t.Fatal(err)
				}
				name := hostname
				trust, err := privatetrust.NewCache(nil).Capture(t.Context(), directory, target.Listener.Addr().String(), config.TrustSource{CA: "ca.pem", Hostname: &name})
				if err != nil {
					t.Fatal(err)
				}
				metadata := controlv1.PrivateServiceMetadata{Protocol: controlv1.PrivateServiceProtocol("http"), TrustRevision: 1}
				if managedTLS {
					pem := string(trust.PEM)
					metadata.TargetTls = &controlv1.PrivateServiceTLS{Hostname: trust.Hostname, Digest: trust.Digest, Pem: &pem}
				}
				key, _ := opaqueid.New(opaqueid.IdempotencyPrefix)
				service, err := f.identity.routes.CreatePrivateService(t.Context(), f.identity.teamID, "private-http", key, metadata)
				if err != nil {
					t.Fatal(err)
				}
				startPrivateHTTPPublisher(t, f, service, target.Listener.Addr().String())
				person, err := f.identity.authority.IdentityContext(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				production, err := tcpconnect.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
				if err != nil {
					t.Fatal(err)
				}
				control := &separatedVisitorControl{Control: production}
				if standalone {
					control.dialAddress = f.sharedQUIC
				}
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(t.Context())
				ready, done := make(chan struct{}), make(chan error, 1)
				go func() {
					done <- tcpconnect.Serve(ctx, listener, tcpconnect.Config{Control: control, PrivateServiceID: service.Id, IdentityID: person.Identity.Id,
						Protocol: "http", TrustRevision: service.TrustRevision, ManagedTLS: service.ManagedTls, ServiceTLS: f.visitorRoots, Ready: func() error { close(ready); return nil }})
				}()
				t.Cleanup(func() {
					cancel()
					select {
					case err := <-done:
						if err != nil {
							t.Errorf("private HTTP connector shutdown: %v", err)
						}
					case <-time.After(5 * time.Second):
						t.Error("private HTTP connector did not join")
					}
				})
				select {
				case <-ready:
				case <-time.After(10 * time.Second):
					t.Fatal("private HTTP connector did not become ready")
				}
				verification := f.visitorRoots.Clone()
				verification.ServerName = service.ManagedTls.Hostname
				transport := &http.Transport{Proxy: nil, TLSClientConfig: verification}
				scheme := "https"
				t.Cleanup(transport.CloseIdleConnections)
				client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
				base := scheme + "://" + listener.Addr().String()
				response, err := client.Post(base+"/once", "application/octet-stream", strings.NewReader("private-operation"))
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || string(body) != "private-operation" || posts.Load() != 1 {
					t.Fatalf("private HTTP operation replayed or changed: %q %v", body, err)
				}
				upgradeCtx, stopUpgrade := context.WithTimeout(t.Context(), 5*time.Second)
				defer stopUpgrade()
				request, _ := http.NewRequestWithContext(upgradeCtx, http.MethodPost, base+"/exec", nil)
				request.Header.Set("Connection", "Upgrade")
				request.Header.Set("Upgrade", "SPDY/3.1")
				response, err = (&http.Client{Transport: transport}).Do(request)
				if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
					t.Fatalf("private SPDY upgrade failed: %v", err)
				}
				upgraded := response.Body.(io.ReadWriteCloser)
				_, _ = io.WriteString(upgraded, "exec-stream")
				data := make([]byte, len("exec-stream"))
				if _, err := io.ReadFull(upgraded, data); err != nil || string(data) != "exec-stream" {
					t.Fatalf("private upgraded bytes: %q %v", data, err)
				}
				_ = upgraded.Close()
				response, err = client.Get(base + "/watch")
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				reader := bufio.NewReader(response.Body)
				if line, err := reader.ReadString('\n'); err != nil || line != "data: ready\n" {
					t.Fatalf("private SSE was buffered: %q %v", line, err)
				}
				device, err := control.PrivateConnectorSigner(t.Context(), person.Identity.Id)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.identity.routes.RevokeVisitorDevice(t.Context(), device.Subject.DeviceID); err != nil {
					t.Fatal(err)
				}
				if _, err := io.Copy(io.Discard, reader); err == nil {
					t.Fatal("revocation did not interrupt the live HTTP stream")
				}
				if posts.Load() != 1 {
					t.Fatal("revocation replayed a previous operation")
				}
				var publicURLs int
				if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.public_urls`).Scan(&publicURLs); err != nil || publicURLs != 0 {
					t.Fatalf("private HTTP created public URL state: %d %v", publicURLs, err)
				}
			})
		}
	}
}
