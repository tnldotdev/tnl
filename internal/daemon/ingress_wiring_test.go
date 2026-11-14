package daemon

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type wiringControl struct {
	ingress.ControlClient
	mu            sync.Mutex
	lease         ingressv1.IngressLease
	admission     ingressv1.PublicServiceVisitorAdmission
	visitors      map[string]bool
	admitted      int
	promoted      int
	closed        int
	promotedReady chan struct{}
	routingReady  chan struct{}
	routingOnce   sync.Once
	load          func() int64
	pendingLoad   int64
	promotedLoad  int64
}

func (*wiringControl) ReadIngressVisitorPolicy(context.Context, string, ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
	return controlv1.VisitorPolicyUpdate{}, ingress.ErrServiceAdmission
}

func (c *wiringControl) RegisterIngress(_ context.Context, r ingressv1.IngressRegistration) (ingressv1.IngressLease, error) {
	now := time.Now()
	l := ingressv1.IngressLease{IngressId: r.IngressId, IngressRunId: r.IngressRunId, IngressLeaseRevision: 1, ProtocolVersion: r.ProtocolVersion,
		Region:             r.Region,
		ConnectionCapacity: r.ConnectionCapacity, RegisteredAt: now, RenewedAt: now, LeaseExpiresAt: now.Add(time.Hour)}
	c.mu.Lock()
	c.lease = l
	c.mu.Unlock()
	return l, nil
}
func (c *wiringControl) DrainIngress(_ context.Context, _ ingressv1.IngressID, r ingressv1.IngressDrainRequest) (ingressv1.IngressLease, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	l := c.lease
	l.Draining, l.DrainDeadline = true, &r.Deadline
	return l, nil
}
func (c *wiringControl) RenewIngress(_ context.Context, _ ingressv1.IngressID, r ingressv1.IngressRenewal) (ingressv1.IngressLease, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lease.RoutingTableRevision = r.RoutingTableRevision
	c.lease.ReportedConnections = r.ReportedConnections
	return c.lease, nil
}
func (*wiringControl) GetIngressRoutingTableSnapshot(context.Context, ingressv1.IngressID, ingressv1.GetIngressRoutingTableSnapshotParams) (ingressv1.IngressRoutingTableSnapshot, error) {
	return ingressv1.IngressRoutingTableSnapshot{}, nil
}
func (c *wiringControl) GetIngressRoutingTableEvents(ctx context.Context, _ ingressv1.IngressID, _ ingressv1.GetIngressRoutingTableEventsParams) (ingressv1.IngressRoutingTablePage, error) {
	if c.routingReady != nil {
		c.routingOnce.Do(func() { close(c.routingReady) })
	}
	<-ctx.Done()
	return ingressv1.IngressRoutingTablePage{}, ctx.Err()
}
func (c *wiringControl) IngestServiceObservations(_ context.Context, _ controlstate.IngressLeaseIdentity, batch serviceaudit.Batch) (controlstate.ServiceObservationResult, error) {
	return controlstate.ServiceObservationResult{Accepted: len(batch.Events)}, nil
}

func (c *wiringControl) AdmitPublicServiceVisitor(_ context.Context, id string, claim ingressv1.PublicServiceVisitorClaim) (ingressv1.PublicServiceVisitorAdmission, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLease(id, claim.IngressRunId, claim.IngressLeaseRevision) || claim.IngressPoolId != "ingress-a" ||
		claim.DestinationPort != 443 || claim.Hostname == nil || *claim.Hostname != "pool.example" || claim.ObservedSourceIp != "192.0.2.44" ||
		!opaqueid.Valid(claim.VisitorConnectionId, opaqueid.VisitorConnectionPrefix) || c.admission.ServiceId == "" {
		return ingressv1.PublicServiceVisitorAdmission{}, ingress.ErrServiceAdmission
	}
	if c.visitors == nil {
		c.visitors = make(map[string]bool)
	}
	c.visitors[claim.VisitorConnectionId] = false
	c.admitted++
	if c.load != nil {
		c.pendingLoad = c.load()
	}
	admission := c.admission
	admission.VisitorConnectionId = claim.VisitorConnectionId
	admission.ConnectedRelays = append([]ingressv1.ServiceRelay(nil), admission.ConnectedRelays...)
	return admission, nil
}
func (c *wiringControl) PublicServiceVisitorStatus(_ context.Context, id string, lookup ingressv1.PublicServiceVisitorLookup) (ingressv1.PublicServiceVisitorStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	promoted, found := c.visitors[lookup.VisitorConnectionId]
	if !found || !c.currentLease(id, lookup.IngressRunId, lookup.IngressLeaseRevision) {
		return ingressv1.PublicServiceVisitorStatus{}, ingress.ErrServiceAdmission
	}
	state := ingressv1.PublicServiceVisitorAuthenticated
	if promoted {
		state = ingressv1.PublicServiceVisitorAllowed
	}
	return ingressv1.PublicServiceVisitorStatus{State: state, ValidUntil: c.admission.ExpiresAt}, nil
}
func (c *wiringControl) PromotePublicServiceVisitor(_ context.Context, id string, lookup ingressv1.PublicServiceVisitorLookup) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	promoted, found := c.visitors[lookup.VisitorConnectionId]
	if !found || !c.currentLease(id, lookup.IngressRunId, lookup.IngressLeaseRevision) {
		return ingress.ErrServiceAdmission
	}
	if !promoted {
		if c.load != nil {
			c.promotedLoad = c.load()
		}
		c.visitors[lookup.VisitorConnectionId] = true
		c.promoted++
		if c.promotedReady != nil && c.promoted == 1 {
			close(c.promotedReady)
		}
	}
	return nil
}
func (c *wiringControl) ClosePublicServiceVisitor(_ context.Context, id string, lookup ingressv1.PublicServiceVisitorLookup) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id != c.lease.IngressId || lookup.IngressRunId != c.lease.IngressRunId || lookup.IngressLeaseRevision != c.lease.IngressLeaseRevision {
		return ingress.ErrServiceAdmission
	}
	if _, found := c.visitors[lookup.VisitorConnectionId]; found {
		delete(c.visitors, lookup.VisitorConnectionId)
		c.closed++
	}
	return nil
}

func (c *wiringControl) ClosedServiceRuns(_ context.Context, id string, lookup ingressv1.ServiceRunClosureLookup) (ingressv1.ServiceRunClosures, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLease(id, lookup.IngressRunId, lookup.IngressLeaseRevision) {
		return ingressv1.ServiceRunClosures{}, ingress.ErrServiceAdmission
	}
	return ingressv1.ServiceRunClosures{Closed: []ingressv1.ServiceRunReference{}}, nil
}

// currentLease requires the caller to hold mu.
func (c *wiringControl) currentLease(id, run string, revision int64) bool {
	return id == c.lease.IngressId && run == c.lease.IngressRunId && revision == c.lease.IngressLeaseRevision &&
		c.lease.LeaseExpiresAt.After(time.Now()) && !c.lease.Draining
}

func TestProductionIngressPoolForwardingAndNoReplay(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("committed_failure=%t", fail), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			ref := tunnelv1.ServicePublisherConnectionRef{
				ServiceID: wiringServiceID(t, opaqueid.ServicePrefix), ServiceRunID: wiringServiceID(t, opaqueid.ServiceRunPrefix), RunNumber: 2,
				PublisherConnectionID: wiringServiceID(t, opaqueid.PublisherConnectionPrefix), ConnectionAssignmentRevision: 1, RelayServiceID: "relay",
			}
			control := &wiringControl{routingReady: make(chan struct{}), promotedReady: make(chan struct{})}
			ca := newTestCertificateAuthority(t)
			material := ca.issue(t, "pool.example")
			certificate, err := tls.X509KeyPair(material.certificatePEM, material.privateKeyPEM)
			if err != nil {
				t.Fatal(err)
			}
			secure := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
			relay, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var workers sync.WaitGroup
			var streams atomic.Int32
			var relayPublisher atomic.Pointer[tunnel.Session]
			registered := make(chan *tunnel.Session, 1)
			forwarded := make(chan tunnelv1.ServiceForwardingHeader, 4)
			publisherResult := make(chan error, 4)
			workers.Go(func() {
				for {
					conn, err := relay.Accept()
					if err != nil {
						return
					}
					workers.Go(func() {
						defer conn.Close()
						stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
						defer stop()
						mux, err := muxsession.AcceptTLSYamux(ctx, conn, secure, muxsession.TLSYamuxConfig{})
						if err != nil {
							return
						}
						session, hello, err := tunnel.Accept(ctx, mux, func(_ context.Context, h tunnelv1.Message) error {
							switch h.Role {
							case tunnelv1.Ingress:
								if h.Credential == "0123456789abcdef0123456789abcdef" && h.PublisherConnection == nil && h.ServiceConnection == nil {
									return nil
								}
							case tunnelv1.Publisher:
								if h.Credential == "service-publisher-credential" && h.PublisherConnection == nil && h.ServiceConnection != nil && *h.ServiceConnection == ref {
									return nil
								}
							}
							return fmt.Errorf("unexpected service fixture authentication")
						})
						if err != nil {
							_ = mux.Close()
							return
						}
						defer session.Close()
						if hello.Role == tunnelv1.Publisher {
							registered <- session
							select {
							case <-ctx.Done():
							case <-session.Done():
							}
							return
						}
						for {
							incoming, err := session.AcceptInternalForwardingStream(ctx)
							if err != nil {
								return
							}
							streams.Add(1)
							workers.Go(func() {
								defer incoming.Stream().Close()
								request, ok := incoming.(*tunnel.IncomingServiceForwardingStream)
								if !ok {
									t.Error("ingress opened a non-service forwarding stream")
									return
								}
								header := request.Header
								if header.Validate() != nil || tunnel.ServiceForwardingRef(header) != ref || header.PublicService == nil || header.PublicService.DestinationPort != 443 || header.SourceIP != "192.0.2.44" {
									t.Error("ingress changed the control-selected service run or forwarding identity", header)
									return
								}
								control.mu.Lock()
								current := control.currentLease(header.PublicService.IngressID, header.PublicService.IngressRunID, int64(header.PublicService.IngressLeaseRevision))
								control.mu.Unlock()
								if !current {
									t.Error("service forwarding lost the current ingress lease")
									return
								}
								forwarded <- header
								upstream, err := relayPublisher.Load().OpenServiceForwardingStream(ctx, header)
								if err != nil {
									t.Error("open publisher service stream", err)
									return
								}
								defer upstream.Close()
								if incoming.Accept() != nil {
									return
								}
								_, _ = streamcopy.Copy(incoming.Stream(), upstream)
							})
						}
					})
				}
			})
			stopFixture := sync.OnceFunc(func() { cancel(); _ = relay.Close(); workers.Wait() })
			t.Cleanup(stopFixture)
			setup, stopSetup := context.WithTimeout(ctx, 5*time.Second)
			defer stopSetup()
			transport, err := (muxsession.TLSYamuxConnector{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: ca.roots}}).Connect(setup, muxsession.Endpoint{Address: relay.Addr().String(), ServerName: "pool.example"})
			if err != nil {
				t.Fatal(err)
			}
			publisher, err := tunnel.Dial(setup, transport, tunnelv1.Message{
				Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Publisher,
				Credential: "service-publisher-credential", ServiceConnection: &ref,
			})
			if err != nil {
				_ = transport.Close()
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = publisher.Close() })
			relayPublisher.Store(wiringServiceAwait(t, registered))
			workers.Go(func() {
				for {
					incoming, err := publisher.AcceptServiceForwardingStream(ctx)
					if err != nil {
						return
					}
					workers.Go(func() {
						publisherResult <- serveWiringServiceVisitor(ctx, incoming, secure, ref, fail, control.promotedReady)
					})
				}
			})
			now := time.Now()
			primary := ingressv1.ServiceRelay{
				PublisherConnectionId: ref.PublisherConnectionID, ConnectionSlot: 0, ConnectionAssignmentRevision: 1,
				RelayServiceId: ref.RelayServiceID, RelayId: "relay", RelayRunId: wiringServiceID(t, opaqueid.RelayRunPrefix), RelayLeaseRevision: 1,
				LeaseExpiresAt: now.Add(time.Hour), InternalRelayAddress: relay.Addr().String(), TlsServerName: "pool.example",
			}
			alternate := primary
			alternate.PublisherConnectionId, alternate.ConnectionSlot, alternate.RelayServiceId = wiringServiceID(t, opaqueid.PublisherConnectionPrefix), 1, "alternate-relay"
			alternate.RelayId, alternate.RelayRunId = "alternate-relay", wiringServiceID(t, opaqueid.RelayRunPrefix)
			// control supplies the selected run; the daemon only forwards its admission.
			control.admission = ingressv1.PublicServiceVisitorAdmission{
				ServiceId: ref.ServiceID, ServiceRunId: ref.ServiceRunID, RunNumber: int64(ref.RunNumber),
				ExpiresAt: now.Add(time.Minute), ConnectedRelays: []ingressv1.ServiceRelay{primary, alternate},
			}
			limits := trafficlimits.Default()
			control.admission.Traffic = ingressv1.IngressTrafficLimits{Connections: limits.Connections, Rate: limits.Rate, RatePerNs: int64(limits.Period()),
				Burst: limits.Burst, UploadBytes: limits.UploadBytes, DownloadBytes: limits.DownloadBytes}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			d := &daemon{ctx: ctx, cancel: cancel, relayClientTLS: &tls.Config{RootCAs: ca.roots}, componentDone: make(chan error, 1)}
			metrics := observability.New("ingress")
			t.Cleanup(func() { _ = metrics.Shutdown(context.Background()) })
			settings := ingressSettingsFrom(daemonconfig.Config{
				VisitorConnectionLimit: 16, LeaseRenewalInterval: time.Minute, ControlRetryInterval: time.Millisecond, RoutingTableWait: time.Second,
				RequireProxyHeader: true, IngressTrustedProxies: []string{"127.0.0.1/32"},
			})
			if err := d.startIngressRuntime(ctx, settings, metrics, ingressRuntimeConfig{client: control, ingressID: "ingress", listener: listener, clusterSecret: "0123456789abcdef0123456789abcdef"}); err != nil {
				_ = listener.Close()
				t.Fatal(err)
			}
			stopDaemon := sync.OnceValue(func() error { return d.shutdown(time.Second) })
			t.Cleanup(func() {
				if err := stopDaemon(); err != nil {
					t.Error(err)
				}
			})
			wiringServiceAwait(t, control.routingReady)
			control.mu.Lock()
			control.load = d.ingresses[0].load
			control.mu.Unlock()
			if got := d.ingresses[0].load(); got != 0 {
				t.Fatal("idle ingress reported physical visitors", got)
			}
			if !d.ingresses[0].controller.Ready(time.Now()) {
				t.Fatal("production controller not ready after installing its empty snapshot")
			}
			httpTransport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: ca.roots}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != "pool.example:443" {
					return nil, fmt.Errorf("unexpected service destination %q", address)
				}
				connection, err := (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
				if err != nil {
					return nil, err
				}
				metadata, err := proxyproto.Encode(proxyproto.Header{
					Source: netip.MustParseAddrPort("192.0.2.44:42000"), Destination: netip.MustParseAddrPort("203.0.113.8:443"),
				})
				if err == nil {
					_, err = io.Copy(connection, bytes.NewReader(metadata))
				}
				if err != nil {
					_ = connection.Close()
					return nil, err
				}
				return connection, nil
			}}
			defer httpTransport.CloseIdleConnections()
			client := &http.Client{Transport: httpTransport, Timeout: 2 * time.Second}
			response, err := client.Get("https://pool.example/")
			if fail {
				if err == nil {
					_ = response.Body.Close()
					t.Fatal("committed failure unexpectedly succeeded")
				}
			} else {
				if err != nil {
					t.Fatalf("production ingress did not forward the control-selected service run: %v", err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || response.StatusCode != 200 || string(body) != "pong" {
					t.Fatalf("forwarded response %q %v", body, err)
				}
			}
			if err := wiringServiceAwait(t, publisherResult); err != nil {
				t.Fatal("publisher service stream", err)
			}
			header := wiringServiceAwait(t, forwarded)
			if tunnel.ServiceForwardingRef(header) != ref || header.ServiceRunID != ref.ServiceRunID || header.RunNumber != 2 {
				t.Fatal("forwarded another service run", header)
			}
			if err := stopDaemon(); err != nil {
				t.Fatal(err)
			}
			stopFixture()
			if count := streams.Load(); count != 1 {
				t.Fatalf("forwarded streams=%d; want one with no replay", count)
			}
			control.mu.Lock()
			admitted, promoted, closed, retained := control.admitted, control.promoted, control.closed, len(control.visitors)
			pendingLoad, promotedLoad := control.pendingLoad, control.promotedLoad
			control.mu.Unlock()
			if admitted != 1 || closed != 1 || retained != 0 || !fail && promoted != 1 {
				t.Fatalf("service admission did not finish exactly once: admitted=%d promoted=%d closed=%d retained=%d", admitted, promoted, closed, retained)
			}
			if pendingLoad != 1 || !fail && promotedLoad != 1 || d.ingresses[0].load() != 0 {
				t.Fatalf("physical visitor counted more than once: pending=%d promoted=%d closed=%d", pendingLoad, promotedLoad, d.ingresses[0].load())
			}
			if len(forwarded) != 0 || len(publisherResult) != 0 {
				t.Fatal("committed service stream was replayed")
			}
		})
	}
}

func wiringServiceID(t *testing.T, prefix string) string {
	t.Helper()
	id, err := opaqueid.New(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func wiringServiceAwait[T any](t *testing.T, values <-chan T) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("service wiring did not reach the expected lifecycle boundary")
		var zero T
		return zero
	}
}

func serveWiringServiceVisitor(ctx context.Context, incoming *tunnel.IncomingServiceForwardingStream, secure *tls.Config, ref tunnelv1.ServicePublisherConnectionRef, fail bool, promoted <-chan struct{}) error {
	defer incoming.Stream().Close()
	if err := incoming.Stream().SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if incoming.Header.Validate() != nil || tunnel.ServiceForwardingRef(incoming.Header) != ref {
		return fmt.Errorf("publisher received another service run")
	}
	if err := incoming.Accept(); err != nil {
		return err
	}
	metadata, remaining, err := proxyproto.Decode(incoming.Stream())
	if err != nil {
		return err
	}
	if metadata.Source != netip.MustParseAddrPort("192.0.2.44:42000") || metadata.Destination != netip.MustParseAddrPort("203.0.113.8:443") {
		return fmt.Errorf("service forwarding changed trusted PROXY metadata")
	}
	if fail {
		var committed [1]byte
		_, err := io.ReadFull(remaining, committed[:])
		return err
	}
	visitor := tls.Server(&wiringReaderConn{Conn: incoming.Stream(), reader: remaining}, secure)
	defer visitor.Close()
	if err := visitor.HandshakeContext(ctx); err != nil {
		return err
	}
	if visitor.ConnectionState().ServerName != "pool.example" {
		return fmt.Errorf("publisher received another TLS hostname")
	}
	request, err := http.ReadRequest(bufio.NewReader(visitor))
	if err != nil {
		return err
	}
	defer request.Body.Close()
	if request.Host != "pool.example" || request.Method != http.MethodGet || request.URL.String() != "/" {
		return fmt.Errorf("publisher received another HTTP request")
	}
	select {
	case <-promoted:
	case <-ctx.Done():
		return ctx.Err()
	}
	_, err = io.WriteString(visitor, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong")
	return err
}

type wiringReaderConn struct {
	net.Conn
	reader io.Reader
}

func (c *wiringReaderConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
