package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
	"go.opentelemetry.io/otel/trace"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

// this fixture runs the real ingress forwarder and relay forwarding acceptor
// with separated TLS sockets, real publisher mux transports, and an HTTPS OTLP
// receiver. publisher-side acceptance is deliberately below application TLS;
// the runtime topology tier covers admission and application HTTP above it.
func TestWireTraceSeparatedInfrastructureExport(t *testing.T) {
	var mu sync.Mutex
	var exported []*tracepb.Span
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		var request collectortrace.ExportTraceServiceRequest
		if err := proto.Unmarshal(data, &request); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		for _, resource := range request.ResourceSpans {
			for _, scope := range resource.ScopeSpans {
				exported = append(exported, scope.Spans...)
			}
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
		body, _ := proto.Marshal(&collectortrace.ExportTraceServiceResponse{})
		_, _ = w.Write(body)
	}))
	defer receiver.Close()
	ca := filepath.Join(t.TempDir(), "collector-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: receiver.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", receiver.URL+"/v1/traces")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE", ca)
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "")
	t.Setenv("OTEL_TRACES_SAMPLER", "parentbased_always_on")
	t.Setenv("OTEL_SDK_DISABLED", "false")
	t.Setenv("OTEL_BSP_SCHEDULE_DELAY", "60000")
	serverTLS := receiver.TLS.Clone()
	roots := x509.NewCertPool()
	roots.AddCert(receiver.Certificate())
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	for _, transport := range []tunnel.Transport{tunnel.TransportQUIC, tunnel.TransportTLSTCP} {
		for _, private := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/private=%t", transport, private), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				owners := make([]*observability.Metrics, 0, 3)
				newOwner := func(role string) context.Context {
					owner, m, err := observability.StartProcess(ctx, role)
					if err != nil {
						t.Fatal(err)
					}
					owners = append(owners, m)
					t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
					return owner
				}
				ingressCtx, relayCtx, publisherCtx := newOwner("ingress"), newOwner("relay"), newOwner("publisher")
				lease := relayv1.RelayLease{RelayServiceId: "relay-service", RelayId: "relay-process", RelayRunId: privateRelayID(opaqueid.RelayRunPrefix), RelayLeaseRevision: 4, LeaseExpiresAt: time.Now().Add(time.Minute), ConnectionCapacity: 4}
				ref := tunnelv1.PublisherConnectionRef{PublicURLID: "public-url", PublishRunID: "publish-run", PublishRunNumber: 3, PublisherConnectionID: "publisher-connection", ConnectionAssignmentRevision: 2, RelayServiceID: lease.RelayServiceId}
				privateRef := tunnelv1.ServicePublisherConnectionRef{ServiceID: privateRelayID(opaqueid.ServicePrefix), ServiceRunID: privateRelayID(opaqueid.ServiceRunPrefix), RunNumber: 3, PublisherConnectionID: privateRelayID(opaqueid.PublisherConnectionPrefix), ConnectionAssignmentRevision: 2, RelayServiceID: lease.RelayServiceId}
				hello := tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: 1, Role: tunnelv1.Publisher, Credential: "publisher-secret", PublisherConnection: &ref}
				if private {
					hello.PublisherConnection = nil
					hello.ServiceConnection = &privateRef
				}
				registry, serviceRegistry := NewRegistry(), NewServiceRegistry()
				defer registry.Close()
				defer serviceRegistry.Close()
				registered := make(chan struct{})
				publisherAddress := traceMuxServer(t, relayCtx, transport, serverTLS, func(owner context.Context, mux muxsession.Session) error {
					session, _, err := tunnel.Accept(owner, mux, func(_ context.Context, h tunnelv1.Message) error {
						if h.Credential != hello.Credential {
							return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
						}
						return nil
					})
					if err != nil {
						return err
					}
					defer session.Close()
					if private {
						paths := newStreamLifetime(session)
						if err := serviceRegistry.insert(&serviceConnection{ref: privateRef, lease: lease, paths: paths}); err != nil {
							return err
						}
					} else {
						claimed := relayv1.ClaimedPublisherConnection{PublicUrlId: ref.PublicURLID, PublishRunId: ref.PublishRunID, PublishRunNumber: 3, PublisherConnectionId: ref.PublisherConnectionID, ConnectionAssignmentRevision: 2, RelayServiceId: lease.RelayServiceId, RelayId: lease.RelayId, RelayRunId: lease.RelayRunId, RelayLeaseRevision: 4}
						c, err := NewPublisherConnection(ref, claimed, session)
						if err != nil {
							return err
						}
						if err = registry.Insert(c); err != nil {
							return err
						}
					}
					close(registered)
					select {
					case <-owner.Done():
					case <-session.Done():
					}
					return nil
				})
				var connector muxsession.Connector = muxsession.TLSYamuxConnector{TLSConfig: clientTLS}
				if transport == tunnel.TransportQUIC {
					connector = muxsession.QUICConnector{TLSConfig: clientTLS}
				}
				mux, err := connector.Connect(ctx, muxsession.Endpoint{Address: publisherAddress, ServerName: "127.0.0.1"})
				if err != nil {
					t.Fatal(err)
				}
				publisher, err := tunnel.Dial(ctx, mux, hello)
				if err != nil {
					t.Fatal(err)
				}
				defer publisher.Close()
				select {
				case <-registered:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				secret := strings.Repeat("s", 32)
				secrets, err := serviceapi.NewBearerSecrets(secret, "")
				if err != nil {
					t.Fatal(err)
				}
				acceptor, err := NewForwardingAcceptor(ForwardingAcceptorConfig{Registry: registry, ServiceRegistry: serviceRegistry, CurrentLease: func() relayv1.RelayLease { return lease }, ClusterSecrets: secrets, StreamCapacity: 4})
				if err != nil {
					t.Fatal(err)
				}
				// internal ingress forwarding is TLS/yamux for both publisher transports.
				address := traceMuxServer(t, relayCtx, tunnel.TransportTLSTCP, serverTLS, acceptor.Accept)
				forwarder, err := ingress.NewForwarder(ingress.ForwarderConfig{Context: ingressCtx, TLSConfig: clientTLS, ClusterSecret: secret})
				if err != nil {
					t.Fatal(err)
				}
				defer forwarder.Close()
				var traceIDs []trace.TraceID
				// two visitors reuse one relay session but must never inherit each other.
				for visitor := range 2 {
					setup, finishSetup := observability.Start(ingressCtx, "fixture.ingress_setup")
					traceIDs = append(traceIDs, trace.SpanContextFromContext(setup).TraceID())
					publisherDone := make(chan error, 1)
					go func() {
						var stream muxsession.Stream
						var received context.Context
						if private {
							v, e := publisher.AcceptServiceForwardingStream(publisherCtx)
							if e != nil {
								publisherDone <- e
								return
							}
							stream = v.Stream()
							received = v.Context()
							if e = v.Accept(); e != nil {
								publisherDone <- e
								return
							}
						} else {
							v, e := publisher.AcceptVisitorStream(publisherCtx)
							if e != nil {
								publisherDone <- e
								return
							}
							stream = v.Stream
							received = v.Context()
							if e = v.Accept(); e != nil {
								publisherDone <- e
								return
							}
						}
						defer stream.Close()
						_, finish := observability.Start(received, "fixture.publisher_receive")
						payload := make([]byte, 8)
						_, e := io.ReadFull(stream, payload)
						if e == nil && string(payload) != "\x16\x03opaque" {
							e = fmt.Errorf("visitor payload changed")
						}
						if e == nil {
							_, e = stream.Write(payload)
						}
						finish(e)
						publisherDone <- e
					}()
					var stream net.Conn
					if private {
						visitorID, e := opaqueid.New(opaqueid.VisitorConnectionPrefix)
						if e != nil {
							t.Fatal(e)
						}
						header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{ProtocolVersion: 1, Kind: tunnelv1.ServiceForwardingStream, ServiceID: privateRef.ServiceID, ServiceRunID: privateRef.ServiceRunID, RunNumber: 3, PublisherConnectionID: privateRef.PublisherConnectionID, ConnectionAssignmentRevision: 2, Connector: &tunnelv1.ConnectorAdmission{SessionID: privateRelayID(opaqueid.ConnectorSessionPrefix), Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: privateRelayID(opaqueid.IdentityPrefix), DeviceID: privateRelayID(opaqueid.VisitorDevicePrefix)}, GrantRevision: 1}, SourceIP: "192.0.2.1", VisitorConnectionID: visitorID, ExpiresAt: lease.LeaseExpiresAt}, RelayServiceID: lease.RelayServiceId, RelayID: lease.RelayId, RelayRunID: lease.RelayRunId, RelayLeaseRevision: 4, LeaseExpiresAt: lease.LeaseExpiresAt}
						relay := ingressv1.ServiceRelay{PublisherConnectionId: privateRef.PublisherConnectionID, ConnectionAssignmentRevision: 2, RelayServiceId: lease.RelayServiceId, RelayId: lease.RelayId, RelayRunId: lease.RelayRunId, RelayLeaseRevision: 4, LeaseExpiresAt: lease.LeaseExpiresAt, InternalRelayAddress: address, TlsServerName: "127.0.0.1"}
						stream, err = forwarder.OpenPrivate(setup, relay, header)
					} else {
						entry := ingressv1.IngressRoutingTableEntry{PublicUrlId: ref.PublicURLID, PublishRunId: ref.PublishRunID, PublishRunNumber: 3, PublicUrlExpiresAt: lease.LeaseExpiresAt, PublisherConnections: []ingressv1.IngressRoutingPublisherConnection{{PublisherConnectionId: ref.PublisherConnectionID, ConnectionAssignmentRevision: 2, RelayServiceId: lease.RelayServiceId, RelayId: lease.RelayId, RelayRunId: lease.RelayRunId, RelayLeaseRevision: 4, LeaseExpiresAt: lease.LeaseExpiresAt, InternalRelayAddress: address, TlsServerName: "127.0.0.1"}}}
						backends, e := forwarder.Backends(entry)
						if e != nil {
							t.Fatal(e)
						}
						stream, err = backends[0].Open(setup, fmt.Sprintf("visitor-%d", visitor))
					}
					if err != nil {
						t.Fatal(err)
					}
					payload := []byte("\x16\x03opaque")
					if _, err = stream.Write(payload); err != nil {
						t.Fatal(err)
					}
					response := make([]byte, len(payload))
					if _, err = io.ReadFull(stream, response); err != nil || !bytes.Equal(payload, response) {
						t.Fatalf("changed bytes: %x %v", response, err)
					}
					_ = stream.Close()
					if err = <-publisherDone; err != nil {
						t.Fatal(err)
					}
					finishSetup(nil)
				}
				if traceIDs[0] == traceIDs[1] {
					t.Fatal("visitor trace leaked through pool")
				}
				// closing drains the forwarding spans before the exporter flush.
				_ = forwarder.Close()
				_ = publisher.Close()
				for _, owner := range owners {
					if err := owner.ForceFlush(ctx); err != nil {
						t.Fatal(err)
					}
				}
				mu.Lock()
				spans := append([]*tracepb.Span{}, exported...)
				mu.Unlock()
				for _, id := range traceIDs {
					assertInfrastructureTrace(t, spans, id, private)
				}
			})
		}
	}
}

func assertInfrastructureTrace(t *testing.T, spans []*tracepb.Span, id trace.TraceID, private bool) {
	t.Helper()
	byName := map[string]*tracepb.Span{}
	for _, span := range spans {
		if bytes.Equal(span.TraceId, id[:]) {
			byName[span.Name] = span
		}
	}
	attempt, relayOpen := "ingress.relay_attempt", "relay.open_visitor_stream"
	if private {
		attempt, relayOpen = "ingress.private_relay_attempt", "relay.open_connector_visitor_stream"
	}
	chain := []string{"fixture.ingress_setup", attempt, relayOpen, "fixture.publisher_receive"}
	for i, name := range chain {
		span := byName[name]
		if span == nil {
			t.Fatalf("trace %s missing %s; spans=%v", id, name, byName)
		}
		if i > 0 && !bytes.Equal(span.ParentSpanId, byName[chain[i-1]].SpanId) {
			t.Fatalf("%s has wrong parent; want %s", name, chain[i-1])
		}
	}
}

func traceMuxServer(t *testing.T, ctx context.Context, transport tunnel.Transport, config *tls.Config, handle func(context.Context, muxsession.Session) error) string {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	var address string
	var accept func() (muxsession.Session, error)
	var closeListener func() error
	if transport == tunnel.TransportQUIC {
		listener, err := muxsession.ListenQUIC("127.0.0.1:0", config, muxsession.QUICConfig{})
		if err != nil {
			t.Fatal(err)
		}
		address = listener.Addr().String()
		accept = func() (muxsession.Session, error) { return listener.Accept(ctx) }
		closeListener = listener.Close
	} else {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address = listener.Addr().String()
		closeListener = listener.Close
		accept = func() (muxsession.Session, error) {
			c, err := listener.Accept()
			if err != nil {
				return nil, err
			}
			return muxsession.AcceptTLSYamux(ctx, c, config, muxsession.TLSYamuxConfig{})
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var workers sync.WaitGroup
		defer workers.Wait()
		for {
			mux, err := accept()
			if err != nil {
				return
			}
			workers.Go(func() { defer mux.Close(); _ = handle(ctx, mux) })
		}
	}()
	t.Cleanup(func() { cancel(); _ = closeListener(); <-done })
	return address
}
