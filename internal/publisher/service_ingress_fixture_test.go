package publisher_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type nativeIngressControl struct {
	ingress.PrivateControl
	port         int
	service, run string
	relays       []ingressv1.ServiceRelay
	lease        ingressv1.IngressLease
	allocation   string
}

func (c nativeIngressControl) GetServiceSnapshot(context.Context, string, ingressv1.GetServiceSnapshotParams) (ingressv1.ServiceSnapshot, error) {
	return ingressv1.ServiceSnapshot{Revision: 1, Entries: []ingressv1.ServiceProjection{{Kind: ingressv1.Upsert, Revision: 1, ServiceId: c.service, ServiceRunId: &c.run, RunNumber: new(int64(1)), ExpiresAt: c.lease.LeaseExpiresAt, ConnectedRelays: &c.relays}}}, nil
}
func (c nativeIngressControl) GetServiceEvents(context.Context, string, ingressv1.GetServiceEventsParams) (ingressv1.ServiceSnapshot, error) {
	return ingressv1.ServiceSnapshot{Revision: 1}, nil
}
func (c nativeIngressControl) AllocateStreamCapacity(context.Context, string, ingressv1.StreamCapacityRequest) (controlv1.StreamCapacityAllocation, error) {
	now := time.Now()
	return controlv1.StreamCapacityAllocation{Id: c.allocation, Resource: controlv1.VisitorResourceScope{Kind: "service", Id: c.service}, RunId: c.run, RunNumber: 1, Capacity: 16, IngressId: c.lease.IngressId, IngressRunId: c.lease.IngressRunId, IngressLeaseRevision: c.lease.IngressLeaseRevision, ObservedAt: now, ValidUntil: now.Add(10 * time.Second), PublisherObserved: true, ReservationKey: bytes.Repeat([]byte{1}, 32)}, nil
}
func (c nativeIngressControl) RetireStreamCapacity(context.Context, string, string, ingressv1.StreamCapacityRetirement) error {
	return nil
}
func (c nativeIngressControl) ReadIngressVisitorPolicy(ctx context.Context, _ string, _ ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
	now := time.Now()
	allocation, _ := c.AllocateStreamCapacity(ctx, "", ingressv1.StreamCapacityRequest{})
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
	return controlv1.VisitorPolicyUpdate{SnapshotRequired: true, Policy: controlv1.VisitorPolicySnapshot{Resource: allocation.Resource, Hostname: "service.example.test", Port: c.port, Issuer: "https://control.example.test", VisitorPolicyRevision: 1, MetadataRevision: 1, KeyRevision: 1, Enabled: true, Public: true, ObservedAt: now, ValidUntil: now.Add(10 * time.Second), VerificationKeys: []controlv1.VisitorVerificationKey{{Id: "fixture", PublicKey: key.Public().(ed25519.PublicKey)}}, StreamAllocations: []controlv1.StreamCapacityAllocation{allocation}}}, nil
}

type nativeIngressForwarder struct {
	t       *testing.T
	server  publisher.ServiceStream
	workers *sync.WaitGroup
	port    uint16
	visitor func() publisher.ServiceVisitorAuthentication
}

func (f nativeIngressForwarder) OpenPrivate(ctx context.Context, _ ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader, events *tunnel.ReturnEvents) (net.Conn, error) {
	if header.Direct == nil || header.Direct.DestinationPort != f.port || header.Validate() != nil {
		return nil, ingress.ErrServiceAdmission
	}
	a, b := net.Pipe()
	f.workers.Go(func() {
		defer b.Close()
		stop := context.AfterFunc(f.t.Context(), func() { _ = b.Close() })
		defer stop()
		metadata, reader, err := proxyproto.Decode(b)
		if err != nil {
			return
		}
		if metadata.Destination.Port() != f.port || metadata.Source.Addr().String() != "127.0.0.1" {
			f.t.Error("original destination/source changed before publisher")
			return
		}
		server := f.server
		if f.visitor != nil {
			server.Visitor = f.visitor()
		}
		var promotion sync.Once
		var promotionErr error
		promote := func(reference tunnelv1.ServiceVisitorReference) error {
			promotion.Do(func() {
				if events == nil || events.Promoted == nil {
					promotionErr = ingress.ErrServiceAdmission
					return
				}
				promoted := header.Admission()
				promoted.Visitor = reference
				promotionErr = events.Promoted(promoted)
			})
			return promotionErr
		}
		switch visitor := server.Visitor.(type) {
		case publisher.CertificateVisitor:
			check := visitor.Check
			visitor.Check = func(ctx context.Context, state tls.ConnectionState) (publisher.ServiceVisitorDecision, error) {
				decision, err := check(ctx, state)
				if err == nil && decision.Allowed && decision.ValidUntil.After(time.Now()) {
					digest := sha256.Sum256(state.PeerCertificates[0].Raw)
					err = promote(tunnelv1.ServiceVisitorReference{Kind: "certificate", ID: hex.EncodeToString(digest[:])})
				}
				return decision, err
			}
			server.Visitor = visitor
		case publisher.ConnectorVisitor:
			check := visitor.Check
			visitor.Check = func(ctx context.Context) (publisher.ServiceVisitorDecision, error) {
				decision, err := check(ctx)
				if err == nil && decision.Allowed && decision.ValidUntil.After(time.Now()) {
					err = promote(tunnelv1.ServiceVisitorReference{Kind: "browser_session", ID: "cs_aaaaaaaaaaaaaaaaaaaaaa"})
				}
				return decision, err
			}
			server.Visitor = visitor
		}
		_ = server.Forward(f.t.Context(), nativeReaderConn{Conn: b, reader: reader})
	})
	return a, nil
}

type nativeReaderConn struct {
	net.Conn
	reader io.Reader
}

func (c nativeReaderConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

// a real public TCP socket and a trusted PROXY v2 hop precede ingress. neither
// the native driver nor the application sends destination metadata or SNI hints
// before PostgreSQL SSLRequest or the server-first MySQL greeting.
func managedIngressListener(t *testing.T, managed publisher.ServiceStream, visitors ...func() publisher.ServiceVisitorAuthentication) string {
	t.Helper()
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = front.Close()
		t.Fatal(err)
	}
	port := front.Addr().(*net.TCPAddr).Port
	id := func(prefix string) string {
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	lease := ingressv1.IngressLease{IngressId: "native", IngressRunId: id(opaqueid.IngressRunPrefix), IngressLeaseRevision: 1, LeaseExpiresAt: time.Now().Add(time.Minute)}
	control := nativeIngressControl{port: port, service: id(opaqueid.ServicePrefix), run: id(opaqueid.ServiceRunPrefix), lease: lease, allocation: id("salloc_")}
	for index := range 2 {
		control.relays = append(control.relays, ingressv1.ServiceRelay{PublisherConnectionId: id(opaqueid.PublisherConnectionPrefix), ConnectionSlot: index, ConnectionAssignmentRevision: 1, RelayServiceId: []string{"a", "b"}[index], RelayId: []string{"relay-a", "relay-b"}[index], RelayRunId: id(opaqueid.RelayRunPrefix), RelayLeaseRevision: 1, InternalRelayAddress: "127.0.0.1:9445", LeaseExpiresAt: lease.LeaseExpiresAt})
	}
	var workers sync.WaitGroup
	forwarder := nativeIngressForwarder{t: t, server: managed, workers: &workers, port: uint16(port)}
	if len(visitors) != 0 {
		forwarder.visitor = visitors[0]
	}
	connector, err := ingress.NewConnector(ingress.ConnectorConfig{Hostname: "ingress.example.test", TLSConfig: &tls.Config{Certificates: managed.TLS.Certificates}, Control: control, VisitorControl: control, Forwarder: forwarder, Routing: new(ingress.ServiceRoutingTable), CurrentLease: func() ingressv1.IngressLease { return lease }})
	if err != nil {
		_ = front.Close()
		_ = backend.Close()
		t.Fatal(err)
	}
	preparation, cancelPreparation := context.WithCancel(t.Context())
	prepared := make(chan error, 1)
	go func() { prepared <- connector.Run(preparation) }()
	t.Cleanup(func() {
		cancelPreparation()
		_ = connector.Close()
		if err := <-prepared; err != nil {
			t.Error(err)
		}
	})
	for deadline := time.Now().Add(3 * time.Second); ; {
		if _, ready := connector.ServiceRoute(control.service, control.run, 1, time.Now()); ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native ingress did not prepare routing and policy")
		}
		time.Sleep(10 * time.Millisecond)
	}
	server, err := ingress.New(backend, ingress.Config{DirectOnly: true, DirectConnector: connector, RequireProxyHeader: true, TrustedProxyPeers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, ServicePortRanges: []tcpport.Range{{First: port, Last: port}}, MaxConnections: 8})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			visitor, err := front.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				defer visitor.Close()
				_ = visitor.SetDeadline(time.Now().Add(15 * time.Second))
				upstream, err := net.DialTimeout("tcp", backend.Addr().String(), time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				_ = upstream.SetDeadline(time.Now().Add(15 * time.Second))
				metadata, err := proxyproto.Encode(proxyproto.Header{Source: visitor.RemoteAddr().(*net.TCPAddr).AddrPort(), Destination: visitor.LocalAddr().(*net.TCPAddr).AddrPort()})
				if err != nil {
					return
				}
				if _, err := upstream.Write(metadata); err != nil {
					return
				}
				_, _ = streamcopy.Copy(visitor, upstream)
			})
		}
	}()
	t.Cleanup(func() {
		_ = front.Close()
		<-acceptDone
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Drain(ctx)
		_ = connector.Close()
		if err := <-done; err != nil {
			t.Error(err)
		}
		workers.Wait()
	})
	return front.Addr().String()
}
