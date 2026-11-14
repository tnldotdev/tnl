package ingress

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type httpsService struct {
	service, run string
	certificate  tls.Certificate
}

type httpsServiceControl struct {
	*publicServiceControlFixture
	services map[string]httpsService
	claims   chan ingressv1.PublicServiceVisitorClaim
}

func (c *httpsServiceControl) AdmitPublicServiceVisitor(_ context.Context, ingress string, claim ingressv1.PublicServiceVisitorClaim) (ingressv1.PublicServiceVisitorAdmission, error) {
	c.claims <- claim
	if ingress != "ingress-a" || claim.Hostname == nil || claim.DestinationPort != 443 || claim.ObservedSourceIp != "192.0.2.4" || claim.IngressLeaseRevision != 1 {
		return ingressv1.PublicServiceVisitorAdmission{}, ErrServiceAdmission
	}
	service, ok := c.services[*claim.Hostname]
	if !ok {
		return ingressv1.PublicServiceVisitorAdmission{}, ErrServiceAdmission
	}
	return ingressv1.PublicServiceVisitorAdmission{
		ServiceId: service.service, ServiceRunId: service.run, RunNumber: 1,
		VisitorConnectionId: claim.VisitorConnectionId, ExpiresAt: time.Now().Add(time.Minute), ConnectedRelays: c.relays,
	}, nil
}

type httpsServiceObservation struct {
	header    tunnelv1.ServiceForwardingHeader
	metadata  proxyproto.Header
	hostname  string
	authority string
}

type httpsServiceForwarder struct {
	ctx      context.Context
	services map[string]httpsService
	observed chan httpsServiceObservation
	workers  sync.WaitGroup
}

func (f *httpsServiceForwarder) OpenPrivate(_ context.Context, _ ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
	service, ok := f.services[header.ServiceID]
	if !ok || header.Validate() != nil || header.ServiceRunID != service.run || header.PublicService.DestinationPort != 443 {
		return nil, ErrServiceAdmission
	}
	client, target := net.Pipe()
	f.workers.Go(func() {
		defer target.Close()
		_ = target.SetDeadline(time.Now().Add(fixtureTimeout))
		metadata, replay, err := proxyproto.Decode(target)
		if err != nil {
			return
		}
		secured := tls.Server(&readerConn{Conn: target, reader: replay}, &tls.Config{Certificates: []tls.Certificate{service.certificate}, MinVersion: tls.VersionTLS13})
		if err := secured.HandshakeContext(f.ctx); err != nil {
			return
		}
		request, err := http.ReadRequest(bufio.NewReader(secured))
		if err != nil {
			return
		}
		defer request.Body.Close()
		f.observed <- httpsServiceObservation{header: header, metadata: metadata, hostname: secured.ConnectionState().ServerName, authority: request.Host}
		response := http.Response{
			StatusCode: http.StatusOK, ProtoMajor: 1, ProtoMinor: 1,
			ContentLength: int64(len(service.service)), Body: io.NopCloser(strings.NewReader(service.service)), Close: true,
		}
		_ = response.Write(secured)
	})
	return client, nil
}

func TestServiceHTTPSRoutesTwoHostnamesOnShared443(t *testing.T) {
	p, base, _, _ := publicServiceTestSetup(t)
	control := &httpsServiceControl{publicServiceControlFixture: base, services: make(map[string]httpsService), claims: make(chan ingressv1.PublicServiceVisitorClaim, 8)}
	targets := &httpsServiceForwarder{ctx: t.Context(), services: make(map[string]httpsService), observed: make(chan httpsServiceObservation, 8)}
	roots := x509.NewCertPool()
	for _, hostname := range []string{"web.example.test", "api.example.test"} {
		service := httpsService{
			service: publicServiceTestID(t, opaqueid.ServicePrefix), run: publicServiceTestID(t, opaqueid.ServiceRunPrefix),
			certificate: visitorfixture.Certificate(t, hostname),
		}
		control.services[hostname], targets.services[service.service] = service, service
		roots.AddCert(service.certificate.Leaf)
	}
	p.config.Control, p.config.Forwarder = control, targets
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(listener, Config{
		PublicServices: p, RequireProxyHeader: true, TrustedProxyPeers: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, MaxConnections: 8,
	})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), fixtureTimeout)
		defer cancel()
		if err := server.Drain(stop); err != nil {
			t.Error(err)
		}
		_ = p.Close()
		targets.workers.Wait()
		if err := ingressAwait(t, done); err != nil {
			t.Error(err)
		}
	})
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			connection, err := (&net.Dialer{}).DialContext(ctx, "tcp4", listener.Addr().String())
			if err != nil {
				return nil, err
			}
			metadata, err := proxyproto.Encode(proxyproto.Header{
				Source: netip.MustParseAddrPort("192.0.2.4:42000"), Destination: netip.MustParseAddrPort("203.0.113.8:443"),
			})
			if err == nil {
				_, err = connection.Write(metadata)
			}
			if err != nil {
				connection.Close()
				return nil, err
			}
			return connection, nil
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: fixtureTimeout}
	for _, hostname := range []string{"web.example.test", "api.example.test"} {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+hostname+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		service := control.services[hostname]
		if err != nil || response.StatusCode != http.StatusOK || string(body) != service.service {
			t.Fatal("shared HTTPS selected another service", hostname, string(body), err)
		}
		claim := ingressAwait(t, control.claims)
		observed := ingressAwait(t, targets.observed)
		if claim.Hostname == nil || *claim.Hostname != hostname || claim.DestinationPort != 443 ||
			observed.hostname != hostname || observed.authority != hostname || observed.header.ServiceID != service.service || observed.header.ServiceRunID != service.run ||
			observed.metadata.Source != netip.MustParseAddrPort("192.0.2.4:42000") || observed.metadata.Destination != netip.MustParseAddrPort("203.0.113.8:443") {
			t.Fatal("service selection, TLS, authority, or trusted metadata changed")
		}
	}
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://unknown.example.test/", nil)
	if response, err := client.Do(request); err == nil {
		response.Body.Close()
		t.Fatal("unknown hostname reached a default service")
	}
	if claim := ingressAwait(t, control.claims); claim.Hostname == nil || *claim.Hostname != "unknown.example.test" {
		t.Fatal("unknown hostname was silently changed")
	}
	select {
	case <-targets.observed:
		t.Fatal("unknown hostname opened another service's TLS frontend")
	default:
	}
}

func TestServiceHTTPSRequiresHostnameOnlyOnSharedPort(t *testing.T) {
	for _, test := range []struct {
		port     uint16
		hostname string
	}{
		{443, ""}, {443, "INVALID.example.test"}, {443, "web.example.test:443"},
		{20000, "web.example.test"}, {80, ""},
	} {
		p, control, forwarder, _ := publicServiceTestSetup(t)
		connection, client := net.Pipe()
		err := p.AcceptPublic(t.Context(), connection, netip.MustParseAddrPort("192.0.2.4:42000"), netip.AddrPortFrom(netip.MustParseAddr("203.0.113.8"), test.port), test.hostname, nil)
		connection.Close()
		client.Close()
		if !errors.Is(err, ErrServiceAdmission) || forwarder.count() != 0 || control.closed != 0 || p.Load() != 0 {
			t.Fatal("invalid selector acquired admission or forwarded bytes", test, err)
		}
	}
}
