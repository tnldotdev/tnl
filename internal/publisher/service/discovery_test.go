package service

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/tnldotdev/tnl/internal/config"
	publisherdiscovery "github.com/tnldotdev/tnl/internal/publisher/target/discovery"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
)

type discoveryProvider func(context.Context, publisherdiscovery.Request) (publisherdiscovery.ResolvedTarget, error)

func (f discoveryProvider) Discover(ctx context.Context, request publisherdiscovery.Request) (publisherdiscovery.ResolvedTarget, error) {
	return f(ctx, request)
}

// this fixture traverses the actual managed publisher's PROXY metadata,
// visitor PostgreSQL SSLRequest/TLS, target SSLRequest/TLS and stream copying.
// a local DNS responder models RDS failover without a public DNS dependency.
func TestDiscoveredPostgresDNSFailoverAndResourceFencePreserveActiveStream(t *testing.T) {
	const hostname = "database.abc.us-east-1.rds.amazonaws.com"
	certificate, _ := managedTestCertificate(t, hostname)
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[1]}))
	sum := sha256.Sum256([]byte(ca))
	var destination atomic.Value
	destination.Store("127.0.0.1")
	var lookups atomic.Int32
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsServer := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		for _, q := range request.Question {
			address := destination.Load().(string)
			kind, queryType := "A", uint16(dns.TypeA)
			if address == "::1" {
				kind, queryType = "AAAA", dns.TypeAAAA
			}
			if q.Name == hostname+"." && q.Qtype == queryType {
				lookups.Add(1)
				rr, _ := dns.NewRR(fmt.Sprintf("%s 0 IN %s %s", q.Name, kind, address))
				response.Answer = append(response.Answer, rr)
			}
		}
		_ = w.WriteMsg(response)
	})}
	go dnsServer.ActivateAndServe()
	defer dnsServer.Shutdown()
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", packet.LocalAddr().String())
	}}
	defer func() { net.DefaultResolver = previous }()
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	_, port, _ := net.SplitHostPort(first.Addr().String())
	second, err := net.Listen("tcp6", "[::1]:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	var firstDials, secondDials atomic.Int32
	serve := func(listener net.Listener, dials *atomic.Int32) {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			dials.Add(1)
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				var ssl [8]byte
				if _, err := io.ReadFull(conn, ssl[:]); err != nil || ssl != targettransport.PostgresSSLRequest {
					return
				}
				if _, err := conn.Write([]byte{'S'}); err != nil {
					return
				}
				secure := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}})
				if secure.HandshakeContext(t.Context()) == nil {
					var startup [8]byte
					if _, err := io.ReadFull(secure, startup[:]); err != nil || startup != [8]byte{0, 0, 0, 8, 0, 3, 0, 0} {
						return
					}
					if _, err := secure.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}); err != nil {
						return
					}
					_, _ = io.Copy(secure, secure)
				}
			}()
		}
	}
	go serve(first, &firstDials)
	go serve(second, &secondDials)
	var replaced atomic.Bool
	resolver, err := publisherdiscovery.New(discoveryProvider(func(context.Context, publisherdiscovery.Request) (publisherdiscovery.ResolvedTarget, error) {
		id := "db-original"
		if replaced.Load() {
			id = "db-replacement"
		}
		return publisherdiscovery.ResolvedTarget{Address: net.JoinHostPort(hostname, port), ServerName: hostname, CA: ca, CADigest: hex.EncodeToString(sum[:]), ARN: "arn:aws:rds:us-east-1:123456789012:db:database", ResourceID: id, Protocol: "postgres"}, nil
	}), publisherdiscovery.Options{TTL: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	source, err := resolver.Prepare(t.Context(), publisherdiscovery.Request{Type: "rds", Region: "us-east-1", Instance: "database", Protocol: "postgres"})
	if err != nil {
		t.Fatal(err)
	}
	p, bound, ref, visitorVerification := privateFixture(t, net.JoinHostPort(hostname, port))
	p.targetResolver, p.managedProtocol = source, config.ProtocolPostgres
	open := func() (net.Conn, <-chan error) {
		front, back := net.Pipe()
		_ = front.SetDeadline(time.Now().Add(5 * time.Second))
		done := make(chan error, 1)
		header := privateHeader(t, ref)
		go func() { defer back.Close(); done <- bound.serveBody(t.Context(), ref, back, header) }()
		metadata, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("203.0.113.1:25443")})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := front.Write(metadata); err != nil {
			t.Fatal(err)
		}
		return front, done
	}
	connect := func() (net.Conn, <-chan error) {
		front, done := open()
		if _, err := front.Write(targettransport.PostgresSSLRequest[:]); err != nil {
			t.Fatal(err)
		}
		var accepted [1]byte
		if _, err := io.ReadFull(front, accepted[:]); err != nil || accepted[0] != 'S' {
			t.Fatal("visitor PG negotiation", err)
		}
		secure := tls.Client(front, visitorVerification.Clone())
		if err := secure.HandshakeContext(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := secure.Write([]byte{0, 0, 0, 8, 0, 3, 0, 0}); err != nil {
			t.Fatal(err)
		}
		var authenticated [9]byte
		if _, err := io.ReadFull(secure, authenticated[:]); err != nil || authenticated != [9]byte{'R', 0, 0, 0, 8, 0, 0, 0, 0} {
			t.Fatal("native PostgreSQL authentication", err)
		}
		return secure, done
	}
	echo := func(conn net.Conn, data string) {
		t.Helper()
		if _, err := io.WriteString(conn, data); err != nil {
			t.Fatal(err)
		}
		out := make([]byte, len(data))
		if _, err := io.ReadFull(conn, out); err != nil || string(out) != data {
			t.Fatal("active SQL stream interrupted or replayed", err)
		}
	}
	active, activeDone := connect()
	defer active.Close()
	echo(active, "first query")
	destination.Store("::1")
	newConnection, newDone := connect()
	echo(newConnection, "second query")
	newConnection.Close()
	<-newDone
	if firstDials.Load() != 1 || secondDials.Load() != 1 || lookups.Load() < 2 {
		t.Fatalf("new connections did not re-resolve DNS: first=%d second=%d lookups=%d", firstDials.Load(), secondDials.Load(), lookups.Load())
	}
	replaced.Store(true)
	time.Sleep(2 * time.Millisecond)
	fenced, fencedDone := open()
	defer fenced.Close()
	if err := <-fencedDone; err == nil || publisherdiscovery.ErrorKind(err) != publisherdiscovery.Changed {
		t.Fatal("resource replacement did not fence new admission", err)
	}
	echo(active, "transaction remains on original connection")
	active.Close()
	<-activeDone
	if firstDials.Load()+secondDials.Load() != 2 {
		t.Fatal("active query was reconnected after resource change")
	}
}
