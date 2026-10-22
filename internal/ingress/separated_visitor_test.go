package ingress

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/publisher"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func startSeparatedPublisher(t *testing.T, f *admissionTransportFixture, c publisher.PublicURLServerConfig) {
	t.Helper()
	c.Hostname = "route.example"
	c.PublicURLID = f.entry.PublicUrlId
	c.PublishRunNumber = uint64(f.entry.PublishRunNumber)
	c.PromoteVisitor = tunnel.NewVisitorPromoter(func(v publisher.Visitor) tunnelv1.VisitorStreamHeader { return v.Header }, func(id string) *tunnel.Session {
		if id == f.ref.PublisherConnectionID {
			return f.publisher
		}
		return nil
	})
	r, err := publisher.NewPublicURLServer(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	ingressWorker(t, func() { cancel(); _ = f.publisher.Close() }, func() error { return r.ServePublisherConnection(ctx, f.publisher, f.ref) })
}

func startSeparatedIngress(t *testing.T, f *admissionTransportFixture, port uint16, protocol string) (*Server, string) {
	t.Helper()
	if port != 443 || protocol != "http" {
		t.Fatal("public ingress accepts HTTP on 443")
	}
	f.entry.AccessMode = ingressv1.Anonymous
	hashedRoutingPolicyForTest(t, &f.entry, "203.0.113.0/24")
	lookup := func() (PublicURL, LookupReason) {
		route, err := f.forwarder.PublicURL(f.entry)
		if err != nil {
			return PublicURL{}, LookupInvalidProjection
		}
		return route, LookupCurrent
	}
	s, address := startIngress(t, Config{RequireProxyHeader: true, TrustedProxyPeers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, Lookup: func(string) (PublicURL, LookupReason) { return lookup() }})
	f.forwarder.SetPromotionHandler(s.PromotePendingAdmission)
	return s, address
}

func separatedVisitor(t *testing.T, address, source string, port uint16) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", address, fixtureTimeout)
	if err != nil {
		t.Fatal(err)
	}
	ownIngressConn(t, c)
	header, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort(source), Destination: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), port)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(header); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSeparatedHTTPIPFilterAndReadinessProof(t *testing.T) {
	f := newAdmissionTransportFixture(t)
	run := publisher.PublishRunIdentity{Hostname: "route.example", PublicURLID: f.entry.PublicUrlId, Number: uint64(f.entry.PublishRunNumber)}
	proof, err := publisher.NewReadinessProof(run, "/health")
	if err != nil {
		t.Fatal(err)
	}
	var application atomic.Int32
	startSeparatedPublisher(t, f, publisher.PublicURLServerConfig{Certificate: testCertificate(t, "route.example"), ReadinessProof: proof, Purpose: controlv1.Oauth, AccessMode: controlv1.Anonymous, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(publisherproxy.ReadinessProbeHeader) != "" {
			t.Error("proof reached application")
		}
		application.Add(1)
		w.WriteHeader(204)
	})})
	s, address := startSeparatedIngress(t, f, 443, "http")
	blocked := tls.Client(separatedVisitor(t, address, "198.51.100.1:40001", 443), &tls.Config{ServerName: "route.example", InsecureSkipVerify: true}) // local fixture certificate.
	if err := blocked.Handshake(); err == nil {
		t.Fatal("source outside IP filter completed visitor TLS")
	}
	_ = blocked.Close()
	for _, test := range []struct {
		source, proof string
		want          int
	}{{"203.0.113.1:40002", "", 204}, {"203.0.113.2:40003", proof.HeaderValue(), 204}} {
		c := tls.Client(separatedVisitor(t, address, test.source, 443), &tls.Config{ServerName: "route.example", InsecureSkipVerify: true}) // local fixture certificate.
		if err := c.Handshake(); err != nil {
			t.Fatal(err)
		}
		_, err := fmt.Fprintf(c, "GET /health HTTP/1.1\r\nHost: route.example\r\nConnection: close\r\n%s\r\n", func() string {
			if test.proof != "" {
				return publisherproxy.ReadinessProbeHeader + ": " + test.proof + "\r\n"
			}
			return ""
		}())
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		_ = c.Close()
		if response.StatusCode != test.want {
			t.Fatalf("source %s status %d; want %d", test.source, response.StatusCode, test.want)
		}
	}
	if application.Load() != 2 {
		t.Fatal(application.Load())
	}
	s.mu.Lock()
	pending := len(s.pendingVisitors)
	s.mu.Unlock()
	if pending > 1 {
		t.Fatalf("pending visitor state leaked: %d", pending)
	}
}
