package daemon

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func startPrivateHTTPPublisher(t *testing.T, f *privateSeparatedFixture, service controlv1.Service, target string, overrides ...publisherservice.RunControl) {
	t.Helper()
	enrollment, err := f.identity.routes.CreatePublisherEnrollment(t.Context(), controlv1.CreatePublisherEnrollmentRequest{TeamId: service.TeamId, ServiceId: &service.Id, Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled, Name: "private-http"})
	if err != nil {
		t.Fatal(err)
	}
	native, identity, err := publisheridentity.EnrollNative(t.Context(), f.identity.state, f.identity.routes, f.identity.authority, enrollment.EnrollmentKey)
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
	var control publisherservice.RunControl = f.identity.routes
	if len(overrides) == 1 {
		control = overrides[0]
	}
	go func() {
		done <- publisherservice.Publish(ctx, publisherservice.RunConfig{Control: control, State: f.identity.state, Access: native.Access, Identity: identity, ServiceID: service.Id, Target: target,
			Metadata: controlv1.ServiceMetadata{Protocol: service.Protocol, TargetTls: service.TargetTls, TrustRevision: service.TrustRevision, PublisherPool: service.PublisherPool}, HeartbeatInterval: heartbeat,
			Ready: func() error { close(ready); return nil }, Connect: func(ctx context.Context, bound *publisherservice.Bound, slot uint8) (publisherservice.SlotSession, error) {
				claimed, err := bound.ConnectSlotWithTransports(ctx, slot, false, quic, tcp)
				if err == nil && f.publisherConnections != nil {
					select {
					case f.publisherConnections <- claimed:
					case <-ctx.Done():
						_ = claimed.Close()
						return nil, context.Cause(ctx)
					}
				}
				return claimed, err
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
		for _, endpoint := range []bool{false, true} {
			t.Run(fmt.Sprintf("standalone=%t/tnl-tls=%t", standalone, endpoint), func(t *testing.T) {
				f := newServiceRuntimeFixture(t, standalone, nil)
				ca := newTestCertificateAuthority(t)
				const hostname = "target.private.integration.test"
				var posts atomic.Int64
				target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if endpoint && r.TLS == nil {
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
				target.TLS = serviceRuntimeTLS(t, ca, hostname)
				target.Config.ErrorLog = log.New(io.Discard, "", 0)
				if endpoint {
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
				trust, err := targettrust.NewCache(nil).Capture(t.Context(), directory, target.Listener.Addr().String(), config.TrustSource{CA: "ca.pem", Hostname: &name})
				if err != nil {
					t.Fatal(err)
				}
				metadata := controlv1.ServiceMetadata{Protocol: controlv1.ServiceProtocol("http"), TrustRevision: 1}
				if endpoint {
					pem := string(trust.PEM)
					metadata.TargetTls = &controlv1.ServiceTargetTLS{Hostname: trust.Hostname, Digest: trust.Digest, Pem: &pem}
				}
				key, _ := opaqueid.New(opaqueid.IdempotencyPrefix)
				service, err := f.identity.routes.CreateService(t.Context(), f.identity.teamID, "private-http", key, metadata)
				if err != nil {
					t.Fatal(err)
				}
				startPrivateHTTPPublisher(t, f, service, target.Listener.Addr().String())
				person, err := f.identity.authority.IdentityContext(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				production, err := connectorstream.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
				if err != nil {
					t.Fatal(err)
				}
				control := production
				quic, tcp := f.connectors()
				listener := startNativeRuntimeConnector(t, f, service, connectorstream.Config{Control: control, IdentityID: person.Identity.Id, RelayQUIC: quic, RelayTCP: tcp}, revokedNativeOwnerStop)
				verification := f.visitorRoots.Clone()
				verification.ServerName = service.Endpoint.Hostname
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
				device, err := control.ConnectorSigner(t.Context(), person.Identity.Id)
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
