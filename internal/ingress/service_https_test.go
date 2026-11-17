package ingress

import (
	"bufio"
	"bytes"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/ingress/clienthello"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type httpsServiceObservation struct {
	header    tunnelv1.ServiceForwardingHeader
	metadata  proxyproto.Header
	hostname  string
	authority string
	prefix    []byte
}

type httpsServiceForwarder struct {
	ctx      context.Context
	services map[string]httpsService
	observed chan httpsServiceObservation
	workers  sync.WaitGroup
}

func (f *httpsServiceForwarder) OpenService(_ context.Context, _ ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader, reserveCapacity func(context.Context) error) (net.Conn, error) {
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
		hello, err := clienthello.InspectClientHello(&readerConn{Conn: target, reader: replay})
		if err != nil {
			return
		}
		secured := tls.Server(&readerConn{Conn: target, reader: hello.Replay()}, &tls.Config{Certificates: []tls.Certificate{service.certificate}, MinVersion: tls.VersionTLS13})
		if err := secured.HandshakeContext(f.ctx); err != nil {
			return
		}
		request, err := http.ReadRequest(bufio.NewReader(secured))
		if err != nil {
			return
		}
		defer request.Body.Close()
		check, cancel := context.WithDeadline(f.ctx, header.ExpiresAt)
		defer cancel()
		if reserveCapacity == nil || reserveCapacity(check) != nil {
			return
		}
		f.observed <- httpsServiceObservation{header: header, metadata: metadata, hostname: secured.ConnectionState().ServerName, authority: request.Host, prefix: hello.Prefix}
		response := http.Response{
			StatusCode: http.StatusOK, ProtoMajor: 1, ProtoMinor: 1,
			ContentLength: int64(len(service.service)), Body: io.NopCloser(strings.NewReader(service.service)), Close: true,
		}
		_ = response.Write(secured)
	})
	return client, nil
}

func TestServiceHTTPSRoutesTwoHostnamesOnShared443(t *testing.T) {
	config, base, _, _ := publicServiceTestConfig(t)
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
	config.Control, config.Forwarder = control, targets
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config.RequireProxyHeader = true
	config.TrustedProxyPeers = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	config.MaxConnections = 8
	server, err := New(listener, config)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	applyServiceRoutingFixture(t, server)
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), fixtureTimeout)
		defer cancel()
		if err := server.Drain(stop); err != nil {
			t.Error(err)
		}
		_ = server.Close()
		targets.workers.Wait()
		if err := ingressAwait(t, done); err != nil {
			t.Error(err)
		}
	})
	startServiceRoutingFixture(t, server)
	sent := make(chan *httpsServiceRecordingConn, 8)
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
			recorded := &httpsServiceRecordingConn{Conn: connection}
			sent <- recorded
			return recorded, nil
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: fixtureTimeout}
	for _, hostname := range []string{"web.example.test", "api.example.test", "WeB.ExAmPlE.TeSt", "API.EXAMPLE.TEST"} {
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
		service := control.services[strings.ToLower(hostname)]
		if err != nil || response.StatusCode != http.StatusOK || string(body) != service.service {
			t.Fatal("shared HTTPS selected another service", hostname, string(body), err)
		}
		observed := ingressAwait(t, targets.observed)
		original := ingressAwait(t, sent).written()
		if len(original) < len(observed.prefix) || !bytes.Equal(original[:len(observed.prefix)], observed.prefix) ||
			!bytes.Contains(observed.prefix, []byte(hostname)) {
			t.Fatal("shared HTTPS changed the original ClientHello bytes")
		}
		if observed.hostname != hostname || observed.authority != hostname || observed.header.ServiceID != service.service || observed.header.ServiceRunID != service.run ||
			observed.header.PublicService.DestinationPort != 443 || observed.metadata.VisitorSourceProof == "" ||
			observed.metadata.Source != netip.MustParseAddrPort("192.0.2.4:42000") || observed.metadata.Destination != netip.MustParseAddrPort("203.0.113.8:443") {
			t.Fatal("service selection, TLS, authority, or trusted metadata changed")
		}
	}
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://unknown.example.test/", nil)
	if response, err := client.Do(request); err == nil {
		response.Body.Close()
		t.Fatal("unknown hostname reached a default service")
	}
	if len(control.claims) != 0 {
		t.Fatal("prepared HTTP selection made a per-visitor control request")
	}
	select {
	case <-targets.observed:
		t.Fatal("unknown hostname opened another service's TLS frontend")
	default:
	}
}

type httpsServiceRecordingConn struct {
	net.Conn
	mu     sync.Mutex
	output bytes.Buffer
}

func (c *httpsServiceRecordingConn) Write(value []byte) (int, error) {
	n, err := c.Conn.Write(value)
	c.mu.Lock()
	defer c.mu.Unlock()
	_, _ = c.output.Write(value[:n])
	return n, err
}

func (c *httpsServiceRecordingConn) written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.output.Bytes())
}

func TestServiceHTTPSRejectsInvalidSNIAndWrongPortBeforeForwarding(t *testing.T) {
	for _, test := range []struct {
		name, sent, wire, hostname string
		port                       uint16
	}{
		{"foreign", "OtHeR.ExAmPlE", "OtHeR.ExAmPlE", "route.example", 443},
		{"trailing_dot", "RoUtE.ExAmPlEx", "RoUtE.ExAmPlE.", "route.example", 443},
		{"port_in_sni", "RoUtE.ExAmPlE:443", "RoUtE.ExAmPlE:443", "route.example", 443},
		{"invalid_sni", "RoUtE..ExAmPlE", "RoUtE..ExAmPlE", "route.example", 443},
		{"non_ascii_long_s", "\u017fervice.example", "\u017fervice.example", "service.example", 443},
		{"non_ascii_kelvin", "\u212a.example", "\u212a.example", "k.example", 443},
		{"control_suffix", "OtHeR.CoNtRoL.ExAmPlE", "OtHeR.CoNtRoL.ExAmPlE", "route.example", 443},
		{"wrong_port", "RoUtE.ExAmPlE", "RoUtE.ExAmPlE", "route.example", 8443},
		{"control_wrong_port", "CoNtRoL.ExAmPlE", "CoNtRoL.ExAmPlE", "route.example", 8443},
	} {
		t.Run(test.name, func(t *testing.T) {
			// the TLS client removes a trailing dot from SNI. replace a same-length
			// placeholder in the captured hello to test the actual wire policy.
			visitor, capture := net.Pipe()
			done := make(chan error, 1)
			go func() {
				done <- tls.Client(visitor, &tls.Config{ServerName: test.sent, MinVersion: tls.VersionTLS13}).HandshakeContext(t.Context())
			}()
			hello, err := clienthello.InspectClientHello(capture)
			_ = capture.Close()
			_ = visitor.Close()
			ingressAwait(t, done)
			if err != nil || hello.ServerName != test.sent || len(test.sent) != len(test.wire) ||
				bytes.Count(hello.Prefix, []byte(test.sent)) != 1 {
				t.Fatal("fixture did not capture the intended ClientHello", err)
			}
			initial := bytes.Replace(hello.Prefix, []byte(test.sent), []byte(test.wire), 1)
			var opened, handedOff atomic.Int32
			config := serviceIngressConfig(t, func(context.Context, tunnelv1.ServiceForwardingHeader, func(context.Context) error) (net.Conn, error) {
				opened.Add(1)
				return nil, ErrServiceAdmission
			})
			control := config.Control.(*httpsServiceControl)
			control.services = map[string]httpsService{test.hostname: control.services["route.example"]}
			config.ServerHostname = "control.example"
			config.HandleControl = func(net.Conn) bool { handedOff.Add(1); return false }
			server, address := startIngress(t, config)
			startServiceRoutingFixture(t, server)
			connection, err := net.DialTimeout("tcp", address, fixtureTimeout)
			if err != nil {
				t.Fatal(err)
			}
			ownIngressConn(t, connection)
			metadata, err := proxyproto.Encode(proxyproto.Header{
				Source:      netip.MustParseAddrPort("192.0.2.4:42000"),
				Destination: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.8"), test.port),
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := writeAll(connection, append(metadata, initial...)); err != nil {
				t.Fatal(err)
			}
			var response [1]byte
			if n, err := connection.Read(response[:]); n != 0 || err == nil {
				t.Fatal("invalid SNI or destination received a TLS response", n, err)
			} else if timeout, ok := errors.AsType[net.Error](err); ok && timeout.Timeout() {
				t.Fatal("ingress did not close the rejected connection", err)
			}
			server.StopAccepting()
			server.active.Wait()
			if opened.Load() != 0 || handedOff.Load() != 0 {
				t.Fatal("invalid SNI or destination selected a service or control handoff", opened.Load(), handedOff.Load())
			}
		})
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

func TestServiceHTTPSRejectsUnboundedInitialBytesBeforeAdmission(t *testing.T) {
	p, control, forwarder, _ := publicServiceTestSetup(t)
	connection, visitor := net.Pipe()
	defer connection.Close()
	defer visitor.Close()
	err := p.AcceptPublic(t.Context(), connection, netip.MustParseAddrPort("192.0.2.4:42000"),
		netip.MustParseAddrPort("203.0.113.8:443"), "web.example.test", make([]byte, clienthello.MaxClientHelloBytes+1))
	if !errors.Is(err, ErrServiceAdmission) || forwarder.count() != 0 || control.closed != 0 || p.Load() != 0 {
		t.Fatal("unbounded inspected prefix acquired admission or forwarded bytes", err)
	}
}
