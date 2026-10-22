package publisher_test

import (
	"context"
	"crypto/tls"
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
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type nativeIngressControl struct {
	ingress.PrivateControl
	port         int
	service, run string
	relays       []ingressv1.PrivateServiceRelay
}

func (c nativeIngressControl) AdmitDirectServiceVisitor(_ context.Context, _ string, claim ingressv1.DirectServiceVisitorClaim) (ingressv1.DirectServiceVisitorAdmission, error) {
	if claim.DestinationPort != c.port || claim.ObservedSourceIp != "127.0.0.1" {
		return ingressv1.DirectServiceVisitorAdmission{}, ingress.ErrPrivateAdmission
	}
	return ingressv1.DirectServiceVisitorAdmission{PrivateServiceId: c.service, PrivateRunId: c.run, RunNumber: 1, VisitorConnectionId: claim.VisitorConnectionId, ExpiresAt: time.Now().Add(time.Minute), ConnectedRelays: c.relays}, nil
}
func (c nativeIngressControl) DirectServiceVisitorStatus(context.Context, string, ingressv1.DirectServiceVisitorLookup) (ingressv1.DirectServiceVisitorStatus, error) {
	return ingressv1.DirectServiceVisitorStatus{State: ingressv1.DirectVisitorAllowed, ValidUntil: time.Now().Add(time.Minute)}, nil
}
func (c nativeIngressControl) CloseDirectServiceVisitor(context.Context, string, ingressv1.DirectServiceVisitorLookup) error {
	return nil
}
func (c nativeIngressControl) PromoteDirectServiceVisitor(context.Context, string, ingressv1.DirectServiceVisitorLookup) error {
	return nil
}

type nativeIngressForwarder struct {
	t       *testing.T
	server  publisher.ManagedStream
	workers *sync.WaitGroup
	port    uint16
	visitor func() publisher.ManagedVisitorAuthentication
}

func (f nativeIngressForwarder) OpenPrivate(ctx context.Context, _ ingressv1.PrivateServiceRelay, header tunnelv1.PrivateForwardingHeader) (net.Conn, error) {
	if header.Direct == nil || header.Direct.DestinationPort != f.port || header.Validate() != nil {
		return nil, ingress.ErrPrivateAdmission
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
func managedIngressListener(t *testing.T, managed publisher.ManagedStream, visitors ...func() publisher.ManagedVisitorAuthentication) string {
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
	control := nativeIngressControl{port: port, service: id(opaqueid.PrivateServicePrefix), run: id(opaqueid.PrivateRunPrefix)}
	for index := range 2 {
		control.relays = append(control.relays, ingressv1.PrivateServiceRelay{PublisherConnectionId: id(opaqueid.PublisherConnectionPrefix), ConnectionSlot: index, ConnectionAssignmentRevision: 1, RelayServiceId: []string{"a", "b"}[index], RelayId: []string{"relay-a", "relay-b"}[index], RelayRunId: id(opaqueid.RelayRunPrefix), RelayLeaseRevision: 1, InternalRelayAddress: "127.0.0.1:9445", LeaseExpiresAt: lease.LeaseExpiresAt})
	}
	var workers sync.WaitGroup
	forwarder := nativeIngressForwarder{t: t, server: managed, workers: &workers, port: uint16(port)}
	if len(visitors) != 0 {
		forwarder.visitor = visitors[0]
	}
	connector, err := ingress.NewPrivateConnector(ingress.PrivateConnectorConfig{Hostname: "ingress.example.test", TLSConfig: &tls.Config{Certificates: managed.TLS.Certificates}, Control: control, DirectControl: control, Forwarder: forwarder, Routing: new(ingress.PrivateRoutingTable), CurrentLease: func() ingressv1.IngressLease { return lease }})
	if err != nil {
		_ = front.Close()
		_ = backend.Close()
		t.Fatal(err)
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
