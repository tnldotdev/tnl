package daemon

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

// each simulated process owns its provider; only the HTTPS collector is shared.
type topologyTraceCollector struct {
	mu     sync.Mutex
	spans  []*tracepb.Span
	owners []*observability.Metrics
}

func newTopologyTraceCollector(t *testing.T) *topologyTraceCollector {
	t.Helper()
	c := &topologyTraceCollector{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/traces" {
			http.NotFound(w, r)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		var batch collectortrace.ExportTraceServiceRequest
		if err != nil || proto.Unmarshal(body, &batch) != nil {
			http.Error(w, "invalid export", 400)
			return
		}
		c.mu.Lock()
		for _, resource := range batch.ResourceSpans {
			for _, scope := range resource.ScopeSpans {
				c.spans = append(c.spans, scope.Spans...)
			}
		}
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
		response, _ := proto.Marshal(&collectortrace.ExportTraceServiceResponse{})
		_, _ = w.Write(response)
	}))
	t.Cleanup(server.Close)
	certificate := filepath.Join(t.TempDir(), "collector.pem")
	if err := os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	// use the production process configuration path, with no external collector.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", server.URL+"/v1/traces")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE", certificate)
	t.Setenv("OTEL_TRACES_SAMPLER", "parentbased_always_on")
	t.Setenv("OTEL_BSP_SCHEDULE_DELAY", "60000")
	t.Cleanup(func() {
		for _, owner := range c.owners {
			if err := owner.Shutdown(context.Background()); err != nil {
				t.Error(err)
			}
		}
	})
	return c
}

func (c *topologyTraceCollector) process(t *testing.T, role string) context.Context {
	t.Helper()
	ctx, owner, err := observability.StartProcess(context.Background(), role)
	if err != nil {
		t.Fatal(err)
	}
	c.owners = append(c.owners, owner)
	return ctx
}

func (c *topologyTraceCollector) assertChain(t *testing.T, names ...string) {
	t.Helper()
	c.assertChainState(t, "", names...)
}

func (c *topologyTraceCollector) assertChainState(t *testing.T, state string, names ...string) {
	t.Helper()
	privateWait(t, 5*time.Second, func(ctx context.Context) (bool, error) {
		for _, owner := range c.owners {
			if err := owner.ForceFlush(ctx); err != nil {
				return false, err
			}
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		// match complete paths, rather than independently finding span names.
		var walk func(int, *tracepb.Span) bool
		walk = func(index int, parent *tracepb.Span) bool {
			if index == len(names) {
				if state == "" {
					return true
				}
				for _, attr := range parent.Attributes {
					if attr.Key == string(observability.State.Key()) && attr.Value.GetStringValue() == state {
						return true
					}
				}
				return false
			}
			for _, span := range c.spans {
				if span.Name != names[index] {
					continue
				}
				if parent != nil && (!bytes.Equal(span.TraceId, parent.TraceId) || !bytes.Equal(span.ParentSpanId, parent.SpanId)) {
					continue
				}
				if len(span.TraceId) != 16 || len(span.SpanId) != 8 {
					continue
				}
				if walk(index+1, span) {
					return true
				}
			}
			return false
		}
		if walk(0, nil) {
			return true, nil
		}
		var got []string
		for _, span := range c.spans {
			for _, name := range names {
				if span.Name == name {
					got = append(got, fmt.Sprintf("%s trace=%x span=%x parent=%x", span.Name, span.TraceId, span.SpanId, span.ParentSpanId))
					break
				}
			}
		}
		return false, fmt.Errorf("missing exported parent chain %v; got %v", names, got)
	})
}

func TestIntegrationPublisherObservabilityPublic(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			collector := newTopologyTraceCollector(t)
			fixture := newSplitPublishFixtureWithOptions(t, "trace", splitPublishOptions{processContext: func(role string) context.Context { return collector.process(t, role) }})
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/denied" {
					t.Error("invalid visitor permission reached the target")
				}
				for _, name := range []string{"traceparent", "tracestate", "baggage"} {
					if r.Header.Get(name) != "" {
						t.Errorf("target received injected %s", name)
					}
				}
				_, _ = io.WriteString(w, "observed")
			}))
			cleanupIntegrationHTTPServer(t, target, fixture.owner)
			quic, tcp := fixture.connectors()
			if transport == "quic" {
				tcp = privateDisabledConnector()
			} else {
				quic = privateDisabledConnector()
			}
			config := fixture.identity.publisherConfig(target.URL, quic, tcp)
			if config.AccessMode != "anonymous" || config.AdmitVisitor != nil || config.PromoteVisitor != nil {
				t.Fatal("public authorization fixture must use default anonymous permission without admission hooks")
			}
			handle := startOwnedIntegrationPublisherContext(t, collector.process(t, "publisher"), fixture.owner, config, nil)
			ready := fixture.waitReady(t, handle)
			response, body, err := fixture.visitor.requestURL(http.MethodGet, ready.PublicURL+"/observed", nil)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 200 || string(body) != "observed" {
				t.Fatalf("response: %s %q", response.Status, body)
			}
			fixture.visitor.transport.CloseIdleConnections()
			collector.assertChain(t, "ingress.open_visitor_stream", "ingress.relay_attempt", "relay.open_visitor_stream", "publisher.visitor", "publisher.visitor_tls")
			collector.assertChain(t, "ingress.open_visitor_stream", "ingress.relay_attempt", "relay.open_visitor_stream", "publisher.visitor", "publisher.http", "publisher.target_connect")
			chain := []string{"ingress.open_visitor_stream", "ingress.relay_attempt", "relay.open_visitor_stream", "publisher.visitor", "publisher.http", "publisher.visitor_authorization", "publisher.authorization"}
			collector.assertChainState(t, "admitted", chain...)
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ready.PublicURL+"/denied", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Tnl-Visitor-Token", "invalid-private-visitor-credential")
			response, _, err = fixture.visitor.request(request)
			if err != nil || response.StatusCode != http.StatusForbidden {
				t.Fatal("invalid supplied credential did not deny the anonymous public visit", err)
			}
			fixture.visitor.transport.CloseIdleConnections()
			collector.assertChainState(t, "denied", chain...)
		})
	}
}

func TestIntegrationPublisherObservabilityPrivate(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			collector := newTopologyTraceCollector(t)
			f := newServiceRuntimeFixtureContext(t, false, nil, true, func(role string) context.Context { return collector.process(t, role) })
			startSeparatedPrivateIngress(t, f, 0, transport, nil)
			startSeparatedPrivateIngress(t, f, 1, transport, nil)
			target := startPrivateEchoTarget(t)
			key, _ := opaqueid.New(opaqueid.IdempotencyPrefix)
			service, err := f.identity.routes.CreateService(t.Context(), f.identity.teamID, "trace", key)
			if err != nil {
				t.Fatal(err)
			}
			enrollment, err := f.identity.routes.CreatePublisherEnrollment(t.Context(), controlv1.CreatePublisherEnrollmentRequest{TeamId: service.TeamId, ServiceId: &service.Id, Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled, Name: "trace"})
			if err != nil {
				t.Fatal(err)
			}
			native, identity, err := publisheridentity.EnrollNative(t.Context(), f.identity.state, f.identity.routes, f.identity.authority, enrollment.EnrollmentKey)
			if err != nil {
				t.Fatal(err)
			}
			quic, tcp := f.connectors()
			if transport == "quic" {
				tcp = privateDisabledConnector()
			} else {
				quic = privateDisabledConnector()
			}
			ctx, cancel := context.WithCancel(collector.process(t, "publisher"))
			ready, done := make(chan struct{}), make(chan error, 1)
			go func() {
				done <- publisherservice.Publish(ctx, publisherservice.RunConfig{Control: f.identity.routes, State: f.identity.state, Access: native.Access, Identity: identity, ServiceID: service.Id, Target: target.address,
					Metadata: controlv1.ServiceMetadata{Protocol: service.Protocol, TargetTls: service.TargetTls, TrustRevision: service.TrustRevision, PublisherPool: service.PublisherPool},
					Ready:    func() error { close(ready); return nil }, Connect: func(ctx context.Context, bound *publisherservice.Bound, slot uint8) (publisherservice.SlotSession, error) {
						return bound.ConnectSlotWithTransports(ctx, slot, false, quic, tcp)
					},
				})
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(12 * time.Second):
					t.Error("publisher did not stop")
				}
			})
			select {
			case <-ready:
			case err := <-done:
				done <- err
				t.Fatalf("publisher failed: %v", err)
			case <-time.After(20 * time.Second):
				t.Fatal("publisher not ready")
			}
			person, err := f.identity.authority.IdentityContext(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			control, err := connectorstream.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			visitorCtx, stop := context.WithCancel(collector.process(t, "client"))
			visitorReady, visitorDone := make(chan struct{}), make(chan error, 1)
			go func() {
				visitorDone <- connectorstream.Serve(visitorCtx, listener, connectorstream.Config{Control: control, ServiceID: service.Id, IdentityID: person.Identity.Id, Protocol: "tcp", TrustRevision: service.TrustRevision, Endpoint: service.Endpoint, ServiceTLS: f.visitorRoots, TransportTLS: f.roots, RelayQUIC: quic, RelayTCP: tcp, Ready: func() error { close(visitorReady); return nil }})
			}()
			t.Cleanup(func() {
				stop()
				select {
				case err := <-visitorDone:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(5 * time.Second):
					t.Error("visitor did not stop")
				}
			})
			select {
			case <-visitorReady:
			case err := <-visitorDone:
				visitorDone <- err
				t.Fatalf("visitor failed: %v", err)
			case <-time.After(10 * time.Second):
				t.Fatal("visitor not ready")
			}
			connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.WriteString(connection, "observed\n"); err != nil {
				t.Fatal(err)
			}
			body := make([]byte, len("observed\n"))
			if _, err := io.ReadFull(connection, body); err != nil || string(body) != "observed\n" {
				t.Fatalf("echo %q: %v", body, err)
			}
			_ = connection.Close()
			collector.assertChain(t, "connector.visitor_setup", "publisher.visitor", "publisher.visitor_admission", "publisher.visitor_tls")
			collector.assertChain(t, "connector.visitor_setup", "publisher.visitor", "publisher.visitor_admission", "publisher.target_connect")
			collector.assertChain(t, "connector.visitor_setup", "publisher.visitor", "publisher.visitor_admission", "publisher.visitor_authorization", "publisher.authorization")
		})
	}
}

func TestIntegrationPublisherObservabilityPublicService(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			collector := newTopologyTraceCollector(t)
			f := newServiceRuntimeFixtureContext(t, false, nil, true, func(role string) context.Context { return collector.process(t, role) })
			process := startSeparatedPrivateIngress(t, f, 0, transport, nil)
			target := startPrivateEchoTarget(t)
			group, protocol, public := "trace", controlv1.Tcp, true
			applied, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), "workload", controlv1.ApplyProjectConfigurationRequest{
				TeamId: f.identity.teamID, SourceFingerprint: strings.Repeat("a", 64),
				Configuration: controlv1.ProjectConfiguration{
					PublisherGroups: map[string]controlv1.ProjectPublisherGroup{group: {Public: &public}},
					Services:        map[string]controlv1.ProjectServiceConfiguration{"echo": {PublisherGroup: &group, Protocol: &protocol, Target: target.address}},
					Webhooks:        map[string]controlv1.ProjectWebhook{},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			startWorkloadPublishers(t, f, group, transport)
			service, err := f.identity.routes.GetService(t.Context(), *applied.Services[0].ServiceId)
			if err != nil || service.Endpoint == nil {
				t.Fatal("public service endpoint", err)
			}
			person, err := f.identity.authority.IdentityContext(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			device, err := f.identity.state.EnsureEnrolledVisitorDevice(t.Context(), person.Identity.Id, f.identity.routes.EnrollVisitorDevice)
			if err != nil {
				t.Fatal(err)
			}
			material, err := f.identity.state.EnsureServiceClientCertificate(t.Context(), person.Identity.Id, service.Id, device.ID, func(ctx context.Context, csr []byte) (controlv1.ServiceClientCertificate, error) {
				return f.identity.routes.IssueServiceClientCertificate(ctx, service.Id, device.ID, csr)
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(collector.process(t, "ingress"))
			defer cancel()
			local, remote := net.Pipe()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer remote.Close()
				_ = process.ingresses[0].publicServices.AcceptPublic(ctx, remote, netip.MustParseAddrPort("192.0.2.4:42000"), netip.AddrPortFrom(netip.MustParseAddr("203.0.113.8"), uint16(service.Endpoint.Port)))
			}()
			t.Cleanup(func() {
				_ = local.Close()
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("public service visitor did not join")
				}
			})
			connection := tls.Client(local, &tls.Config{RootCAs: f.visitorRoots.RootCAs, ServerName: service.Endpoint.Hostname, MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{material.Certificate}})
			_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.WriteString(connection, "observed\n"); err != nil {
				t.Fatal(err)
			}
			body := make([]byte, len("observed\n"))
			if _, err := io.ReadFull(connection, body); err != nil || string(body) != "observed\n" {
				t.Fatalf("public service echo %q: %v", body, err)
			}
			_ = local.Close()
			collector.assertChain(t, "ingress.public_service_visitor_connection", "ingress.private_relay_attempt", "relay.open_connector_visitor_stream", "publisher.visitor", "publisher.visitor_admission", "publisher.visitor_tls")
			collector.assertChain(t, "ingress.public_service_visitor_connection", "ingress.private_relay_attempt", "relay.open_connector_visitor_stream", "publisher.visitor", "publisher.visitor_admission", "publisher.target_connect")
			collector.assertChain(t, "ingress.public_service_visitor_connection", "ingress.private_relay_attempt", "relay.open_connector_visitor_stream", "publisher.visitor", "publisher.visitor_admission", "publisher.visitor_authorization", "publisher.authorization")
		})
	}
}
