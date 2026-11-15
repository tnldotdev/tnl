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
	"time"

	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type serviceRelayOpening func(context.Context, tunnelv1.ServiceForwardingHeader, func(context.Context) error) (net.Conn, error)

type httpsService struct {
	service, run string
	certificate  tls.Certificate
}

type httpsServiceControl struct {
	*publicServiceControlFixture
	services map[string]httpsService
	claims   chan ingressv1.PublicServiceVisitorClaim
	sources  netip.Prefix
	reads    atomic.Int32
}

func (c *httpsServiceControl) ReadIngressServices(_ context.Context, id string, lease ingressv1.IngressLeaseIdentity) (ingressv1.IngressServices, error) {
	c.reads.Add(1)
	now := time.Now()
	snapshot := ingressv1.IngressServices{ObservedAt: now, ValidUntil: now.Add(visitortoken.PolicyLifetime)}
	source := c.sources
	if !source.IsValid() {
		source = netip.MustParsePrefix("192.0.2.4/32")
	}
	ipKey := [32]byte{1}
	prefix, err := ippolicy.Hash(ipKey, source)
	if err != nil {
		return snapshot, err
	}
	for hostname, service := range c.services {
		authority, key, err := visitortoken.IssueVisitorSourceAuthority([32]byte{1}, tunnelv1.VisitorSourceAuthority{
			ServiceID: service.service, ServiceRunID: service.run, RunNumber: 1, EndpointRevision: 1,
			IngressID: id, IngressRunID: lease.IngressRunId, IngressLeaseRevision: uint64(lease.IngressLeaseRevision),
			VisitorPolicyRevision: 1, ValidUntil: snapshot.ValidUntil.Unix(),
		}, now)
		if err != nil {
			return snapshot, err
		}
		wire, err := authority.MarshalBinary()
		if err != nil {
			return snapshot, err
		}
		snapshot.Runs = append(snapshot.Runs, ingressv1.IngressServiceRun{
			ServiceId: service.service, ServiceRunId: service.run, RunNumber: 1, Protocol: controlv1.ServiceProtocolHTTP,
			Hostname: hostname, Port: 443, EndpointRevision: 1, ValidUntil: snapshot.ValidUntil,
			Traffic: c.traffic, ConnectedRelays: c.relays, Anonymous: c.anonymous, SourceAuthority: wire, SourceKey: key[:],
			RecoveryEpisodeId: c.recoveryEpisodeID,
			Ip:                &controlv1.VisitorPolicyIP{Key: ipKey[:], Prefixes: []controlv1.HashedIPPrefix{{Family: controlv1.HashedIPPrefixFamily(prefix.Family), PrefixLength: prefix.Bits, Digest: prefix.Digest}}},
		})
	}
	return snapshot, nil
}

func (c *httpsServiceControl) AdmitPublicServiceVisitor(_ context.Context, _ string, claim ingressv1.PublicServiceVisitorClaim) (ingressv1.PublicServiceVisitorAdmission, error) {
	c.claims <- claim
	return ingressv1.PublicServiceVisitorAdmission{}, errors.New("HTTP traffic called native control admission")
}

type serviceRelayForwarder struct {
	openings []serviceRelayOpening
}

func (f serviceRelayForwarder) OpenService(ctx context.Context, relay ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader, reserveCapacity func(context.Context) error) (net.Conn, error) {
	if header.Validate() != nil || header.PublicService == nil || header.PublicService.DestinationPort != 443 ||
		header.PublisherConnectionID != relay.PublisherConnectionId || header.ConnectionSlot != uint8(relay.ConnectionSlot) ||
		int(header.ConnectionSlot) >= len(f.openings) {
		return nil, ErrServiceAdmission
	}
	return f.openings[header.ConnectionSlot](ctx, header, reserveCapacity)
}

func serviceIngressConfig(t *testing.T, openings ...serviceRelayOpening) Config {
	t.Helper()
	if len(openings) < 1 || len(openings) > 2 {
		t.Fatal("service fixture requires one or two relay slots")
	}
	config, base, _, _ := publicServiceTestConfig(t)
	base.relays = base.relays[:len(openings)]
	config.Control = &httpsServiceControl{
		publicServiceControlFixture: base,
		services: map[string]httpsService{
			"route.example": {service: base.service, run: base.run},
		},
		claims: make(chan ingressv1.PublicServiceVisitorClaim, 8),
	}
	config.Forwarder = serviceRelayForwarder{openings: openings}
	config.RequireProxyHeader = true
	config.TrustedProxyPeers = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	return config
}

type serviceTLSRelay struct {
	connection net.Conn
	opens      atomic.Int32
	header     chan tunnelv1.ServiceForwardingHeader
	capacity   chan func(context.Context) error
	result     chan backendResult
}

func newServiceTLSRelay(t *testing.T, authorized ...<-chan struct{}) *serviceTLSRelay {
	t.Helper()
	if len(authorized) > 1 {
		t.Fatal("service TLS fixture accepts one authorization signal")
	}
	a, b := net.Pipe()
	ownIngressConn(t, a)
	ownIngressConn(t, b)
	relay := &serviceTLSRelay{connection: a, header: make(chan tunnelv1.ServiceForwardingHeader, 1), capacity: make(chan func(context.Context) error, 1), result: make(chan backendResult, 1)}
	certificate := testCertificate(t, "route.example")
	ingressWorker(t, func() { _ = a.Close(); _ = b.Close() }, func() error {
		defer b.Close()
		metadata, replay, err := proxyproto.Decode(b)
		if err != nil {
			relay.result <- backendResult{err: err}
			return nil
		}
		header := <-relay.header
		reserveCapacity := <-relay.capacity
		secured := tls.Server(&testReaderConn{Conn: b, reader: replay}, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})
		request := make([]byte, 4)
		_, err = io.ReadFull(secured, request)
		if err == nil && reserveCapacity != nil {
			check, cancel := context.WithDeadline(t.Context(), header.ExpiresAt)
			err = reserveCapacity(check)
			cancel()
		}
		if err == nil && len(authorized) != 0 {
			select {
			case <-authorized[0]:
			case <-t.Context().Done():
				return t.Context().Err()
			}
		}
		if err == nil {
			_, err = secured.Write([]byte("pong"))
		}
		relay.result <- backendResult{header: metadata, visitorConnectionID: header.VisitorConnectionID, request: string(request), err: err}
		return nil
	})
	return relay
}

func (r *serviceTLSRelay) open(ctx context.Context, header tunnelv1.ServiceForwardingHeader, reserveCapacity func(context.Context) error) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.opens.Add(1) != 1 {
		return nil, errors.New("service TLS fixture unexpectedly opened twice")
	}
	r.header <- header
	r.capacity <- reserveCapacity
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

func (r *serviceFailureRelay) open(_ context.Context, header tunnelv1.ServiceForwardingHeader, _ func(context.Context) error) (net.Conn, error) {
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
	return func(ctx context.Context, _ tunnelv1.ServiceForwardingHeader, _ func(context.Context) error) (net.Conn, error) {
		if entered != nil {
			close(entered)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
}
