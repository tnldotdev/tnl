package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type serviceRelayOpening func(context.Context, tunnelv1.ServiceForwardingHeader) (net.Conn, error)

type serviceRelayForwarder struct {
	openings []serviceRelayOpening
}

func (f serviceRelayForwarder) OpenPrivate(ctx context.Context, relay ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
	if header.Validate() != nil || header.PublicService == nil || header.PublicService.DestinationPort != 443 ||
		header.PublisherConnectionID != relay.PublisherConnectionId || header.ConnectionSlot != uint8(relay.ConnectionSlot) ||
		int(header.ConnectionSlot) >= len(f.openings) {
		return nil, ErrServiceAdmission
	}
	return f.openings[header.ConnectionSlot](ctx, header)
}

func serviceIngressConfig(t *testing.T, openings ...serviceRelayOpening) Config {
	t.Helper()
	if len(openings) < 1 || len(openings) > 2 {
		t.Fatal("service fixture requires one or two relay slots")
	}
	p, base, _, _ := publicServiceTestSetup(t)
	base.relays = base.relays[:len(openings)]
	p.config.Control = &httpsServiceControl{
		publicServiceControlFixture: base,
		services: map[string]httpsService{
			"route.example": {service: base.service, run: base.run},
		},
		claims: make(chan ingressv1.PublicServiceVisitorClaim, 8),
	}
	p.config.Forwarder = serviceRelayForwarder{openings: openings}
	return Config{PublicServices: p, RequireProxyHeader: true,
		TrustedProxyPeers: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
}

type serviceTLSRelay struct {
	connection net.Conn
	opens      atomic.Int32
	header     chan tunnelv1.ServiceForwardingHeader
	result     chan backendResult
}

func newServiceTLSRelay(t *testing.T) *serviceTLSRelay {
	t.Helper()
	a, b := net.Pipe()
	ownIngressConn(t, a)
	ownIngressConn(t, b)
	relay := &serviceTLSRelay{connection: a, header: make(chan tunnelv1.ServiceForwardingHeader, 1), result: make(chan backendResult, 1)}
	certificate := testCertificate(t, "route.example")
	ingressWorker(t, func() { _ = a.Close(); _ = b.Close() }, func() error {
		defer b.Close()
		metadata, replay, err := proxyproto.Decode(b)
		if err != nil {
			relay.result <- backendResult{err: err}
			return nil
		}
		header := <-relay.header
		secured := tls.Server(&testReaderConn{Conn: b, reader: replay}, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})
		request := make([]byte, 4)
		_, err = io.ReadFull(secured, request)
		if err == nil {
			_, err = secured.Write([]byte("pong"))
		}
		relay.result <- backendResult{header: metadata, visitorConnectionID: header.VisitorConnectionID, request: string(request), err: err}
		return nil
	})
	return relay
}

func (r *serviceTLSRelay) open(ctx context.Context, header tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.opens.Add(1) != 1 {
		return nil, errors.New("service TLS fixture unexpectedly opened twice")
	}
	r.header <- header
	return r.connection, nil
}

type serviceFailureRelay struct {
	connection net.Conn
	opens      atomic.Int32
	mu         sync.Mutex
	visitorID  string
}

func newServiceFailureRelay(t *testing.T, visitorBytes int) *serviceFailureRelay {
	t.Helper()
	a, b := net.Pipe()
	ownIngressConn(t, a)
	ownIngressConn(t, b)
	ingressWorker(t, func() { _ = a.Close(); _ = b.Close() }, func() error {
		defer b.Close()
		_, _ = io.Copy(io.Discard, b)
		return nil
	})
	return &serviceFailureRelay{connection: &failAfterProxyConn{Conn: a, visitorBytes: visitorBytes}}
}

func (r *serviceFailureRelay) open(_ context.Context, header tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
	r.opens.Add(1)
	r.mu.Lock()
	r.visitorID = header.VisitorConnectionID
	r.mu.Unlock()
	return r.connection, nil
}

func (r *serviceFailureRelay) visitorConnectionID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.visitorID
}

func waitingServiceRelay(entered chan struct{}) serviceRelayOpening {
	return func(ctx context.Context, _ tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
		if entered != nil {
			close(entered)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
}
