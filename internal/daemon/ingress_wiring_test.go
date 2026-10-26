package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type wiringControl struct {
	ingress.ControlClient
	snapshot    ingressv1.IngressRoutingTableSnapshot
	mu          sync.Mutex
	lease       ingressv1.IngressLease
	allocations map[string]controlv1.StreamCapacityAllocation
}

func (c *wiringControl) AllocateStreamCapacity(_ context.Context, id string, body ingressv1.StreamCapacityRequest) (controlv1.StreamCapacityAllocation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	allocation := controlv1.StreamCapacityAllocation{Id: "salloc_" + strings.TrimPrefix(body.RunId, "pr_"), Resource: body.Resource, RunId: body.RunId, RunNumber: body.RunNumber,
		IngressId: id, IngressRunId: body.IngressRunId, IngressLeaseRevision: body.IngressLeaseRevision, Capacity: body.Capacity, ObservedAt: now, ValidUntil: now.Add(10 * time.Second), PublisherObserved: true, ReservationKey: []byte(strings.Repeat("k", 32))}
	if c.allocations == nil {
		c.allocations = make(map[string]controlv1.StreamCapacityAllocation)
	}
	c.allocations[allocation.Id] = allocation
	return allocation, nil
}

func (c *wiringControl) RetireStreamCapacity(context.Context, string, string, ingressv1.StreamCapacityRetirement) error {
	return nil
}

func (c *wiringControl) ReadIngressVisitorPolicy(_ context.Context, _ string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("w", 32)))
	allocations := []controlv1.StreamCapacityAllocation{}
	for _, allocation := range c.allocations {
		if allocation.Resource == body.Resource {
			allocations = append(allocations, allocation)
		}
	}
	return controlv1.VisitorPolicyUpdate{AfterRevision: body.AfterRevision, Revisions: []int64{}, SnapshotRequired: body.AfterRevision == 0,
		Policy: controlv1.VisitorPolicySnapshot{Resource: body.Resource, Hostname: "pool.example", Port: 443, Issuer: "https://control.example.test", ObservedAt: now, ValidUntil: now.Add(10 * time.Second), Enabled: true, Anonymous: true,
			VisitorPolicyRevision: 1, KeyRevision: 1, VerificationKeys: []controlv1.VisitorVerificationKey{{Id: "fixture", PublicKey: key.Public().(ed25519.PublicKey)}}, WorkloadLeases: []controlv1.VisitorWorkloadLease{}, StreamAllocations: allocations}}, nil
}

func (c *wiringControl) RegisterIngress(_ context.Context, r ingressv1.IngressRegistration) (ingressv1.IngressLease, error) {
	now := time.Now()
	l := ingressv1.IngressLease{IngressId: r.IngressId, IngressRunId: r.IngressRunId, IngressLeaseRevision: 1, ProtocolVersion: r.ProtocolVersion,
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
func (c *wiringControl) GetIngressRoutingTableSnapshot(context.Context, ingressv1.IngressID, ingressv1.GetIngressRoutingTableSnapshotParams) (ingressv1.IngressRoutingTableSnapshot, error) {
	return c.snapshot, nil
}
func (c *wiringControl) GetIngressRoutingTableEvents(ctx context.Context, _ ingressv1.IngressID, _ ingressv1.GetIngressRoutingTableEventsParams) (ingressv1.IngressRoutingTablePage, error) {
	<-ctx.Done()
	return ingressv1.IngressRoutingTablePage{}, ctx.Err()
}
func (c *wiringControl) IngestServiceObservations(_ context.Context, _ controlstate.IngressLeaseIdentity, batch serviceaudit.Batch) (controlstate.ServiceObservationResult, error) {
	return controlstate.ServiceObservationResult{Accepted: len(batch.Events)}, nil
}

func TestProductionIngressPoolForwardingAndNoReplay(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("committed_failure=%t", fail), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
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
						session, _, err := tunnel.Accept(ctx, mux, func(_ context.Context, h tunnelv1.Message) error {
							if h.Role != tunnelv1.Ingress || h.Credential != "0123456789abcdef0123456789abcdef" {
								return fmt.Errorf("unexpected ingress authentication")
							}
							return nil
						})
						if err != nil {
							_ = mux.Close()
							return
						}
						defer session.Close()
						for {
							incoming, err := session.AcceptInternalForwardingStream(ctx)
							if err != nil {
								return
							}
							streams.Add(1)
							workers.Go(func() {
								defer incoming.Stream().Close()
								request, ok := incoming.(*tunnel.IncomingPublicForwardingStream)
								if !ok || request.Header.PublishRunID != fmt.Sprintf("pr_%022d", 444444) {
									t.Error("selected oldest full run")
								}
								if request.Header.Reservation.Validate() != nil || request.Header.Reservation.RunID != request.Header.PublishRunID || request.Header.Reservation.VisitorConnectionID != request.Header.VisitorConnectionID {
									t.Error("forwarding lost its prepared exact-run reservation")
								}
								if incoming.Accept() != nil {
									return
								}
								_, remaining, err := proxyproto.Decode(incoming.Stream())
								if err != nil {
									return
								}
								if fail {
									var b [1]byte
									_, _ = remaining.Read(b[:])
									return
								}
								visitor := tls.Server(&wiringReaderConn{Conn: incoming.Stream(), reader: remaining}, secure)
								defer visitor.Close()
								if err := visitor.HandshakeContext(ctx); err != nil {
									return
								}
								// one finite request, followed by a close-delimited response.
								var b [1]byte
								for tail := ""; tail != "\r\n\r\n"; {
									if _, err := io.ReadFull(visitor, b[:]); err != nil {
										return
									}
									tail += string(b[:])
									if len(tail) > 4 {
										tail = tail[len(tail)-4:]
									}
								}
								_, _ = io.WriteString(visitor, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong")
							})
						}
					})
				}
			})
			t.Cleanup(func() { cancel(); _ = relay.Close(); workers.Wait() })
			now := time.Now()
			control := &wiringControl{snapshot: ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 2}}
			for run := int64(1); run <= 2; run++ {
				available := int64(1)
				if run == 1 {
					available = 0
				}
				entry := ingressv1.IngressRoutingTableEntry{PublicUrlId: "url_0123456789ABCDEFGHIJKL", PublishRunId: fmt.Sprintf("pr_%022d", run*222222), PublishRunNumber: run, CanonicalHostname: "pool.example", PolicyRevision: 1,
					AccessMode: ingressv1.Anonymous, IpPolicy: ingressv1.AllowAll, PublicUrlExpiresAt: now.Add(time.Hour), PublisherConnections: []ingressv1.IngressRoutingPublisherConnection{{ConnectionSlot: 0, PublisherConnectionId: fmt.Sprintf("pc-%d", run), ConnectionAssignmentRevision: 1, RelayServiceId: "relay", RelayId: "relay", RelayRunId: "relay-run", RelayLeaseRevision: 1, LeaseExpiresAt: now.Add(time.Hour), InternalRelayAddress: relay.Addr().String(), TlsServerName: "pool.example", AvailableStreams: &available}}}
				alternate := entry.PublisherConnections[0]
				alternate.ConnectionSlot, alternate.PublisherConnectionId, alternate.RelayServiceId = 1, fmt.Sprintf("alternate-pc-%d", run), "alternate-relay"
				entry.PublisherConnections = append(entry.PublisherConnections, alternate)
				control.snapshot.Entries = append(control.snapshot.Entries, ingressv1.IngressRoutingTableEvent{RoutingTableRevision: run, EntryRevision: 1, Kind: ingressv1.PublicUrlUpsert, PublicUrlId: entry.PublicUrlId, PublishRunNumber: run, CanonicalHostname: entry.CanonicalHostname, Entry: entry, PublicUrlExpiresAt: &entry.PublicUrlExpiresAt, CreatedAt: now})
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			d := &daemon{ctx: ctx, cancel: cancel, relayClientTLS: &tls.Config{RootCAs: ca.roots}, componentDone: make(chan error, 1)}
			metrics := observability.New("ingress")
			t.Cleanup(func() { _ = metrics.Shutdown(context.Background()) })
			settings := ingressSettingsFrom(daemonconfig.Config{VisitorConnectionLimit: 16, LeaseRenewalInterval: time.Minute, ControlRetryInterval: time.Millisecond, RoutingTableWait: time.Second})
			if err := d.startIngressRuntime(ctx, settings, metrics, ingressRuntimeConfig{client: control, ingressID: "ingress", listener: listener, clusterSecret: "0123456789abcdef0123456789abcdef"}); err != nil {
				_ = listener.Close()
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := d.shutdown(time.Second); err != nil {
					t.Error(err)
				}
			})
			deadline := time.Now().Add(2 * time.Second)
			for {
				_, reason := d.ingresses[0].controller.LookupPublicURLs("pool.example", d.ingresses[0].forwarder, time.Now())
				if reason == ingress.LookupCurrent {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("production controller not ready")
				}
				time.Sleep(time.Millisecond)
			}
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.roots}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
			response, err := client.Get("https://pool.example/")
			if fail {
				if err == nil {
					_ = response.Body.Close()
					t.Fatal("committed failure unexpectedly succeeded")
				}
			} else {
				if err != nil {
					t.Fatalf("production pool did not forward around oldest full run: %v", err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || response.StatusCode != 200 || string(body) != "pong" {
					t.Fatalf("forwarded response %q %v", body, err)
				}
			}
			if count := streams.Load(); count != 1 {
				t.Fatalf("forwarded streams=%d; want one with no replay", count)
			}
			control.mu.Lock()
			for _, allocation := range control.allocations {
				if allocation.Capacity >= 32 {
					t.Error("initial preparation took the complete default run limit")
				}
			}
			control.mu.Unlock()
		})
	}
}

type wiringReaderConn struct {
	net.Conn
	reader io.Reader
}

func (c *wiringReaderConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
