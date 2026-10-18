package ingress

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/routebackend"
)

type rawVisitorBackend struct {
	connection net.Conn
	opens      atomic.Int32
}

func testPublicPort(port uint16) *uint16 { return &port }

func (b *rawVisitorBackend) Open(context.Context, string) (net.Conn, error) {
	b.opens.Add(1)
	return b.connection, nil
}

func TestIngressSelectsDatabasePortFromTrustedDestination(t *testing.T) {
	a, b := net.Pipe()
	ownIngressConn(t, a)
	ownIngressConn(t, b)
	backend := &rawVisitorBackend{connection: a}
	received := make(chan proxyproto.Header, 1)
	ingressWorker(t, func() { _ = a.Close(); _ = b.Close() }, func() error {
		defer b.Close()
		header, replay, err := proxyproto.Decode(b)
		if err != nil {
			return err
		}
		var startup [8]byte
		if _, err := io.ReadFull(replay, startup[:]); err != nil {
			return err
		}
		if string(startup[:]) != "startup!" {
			t.Errorf("visitor startup bytes = %q", startup)
		}
		received <- header
		_, err = b.Write([]byte("ready"))
		return err
	})
	usage := newUsageRecorder()
	var httpsLookups atomic.Int32
	_, address := startIngress(t, Config{
		RequireProxyHeader: true, OpenUsage: usage.Open,
		Lookup: func(string) (PublicURL, LookupReason) {
			httpsLookups.Add(1)
			return PublicURL{}, "missing"
		},
		LookupPort: func(port uint16) (PublicURL, LookupReason) {
			if port != 15432 {
				return PublicURL{}, "missing"
			}
			return PublicURL{ID: "public_url_db", PublishRunNumber: 2, PublicPort: testPublicPort(15432),
				AllowAll: true, Backends: []routebackend.Backend{backend}}, ""
		},
	})
	connect := func(port uint16) net.Conn {
		t.Helper()
		client, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		ownIngressConn(t, client)
		header, err := proxyproto.Encode(proxyproto.Header{
			Source:      netip.MustParseAddrPort("198.51.100.3:40001"),
			Destination: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.10"), port),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(header); err != nil {
			t.Fatal(err)
		}
		return client
	}
	missing := connect(15433)
	if _, err := missing.Write([]byte("startup!")); err != nil {
		t.Fatal(err)
	}
	var closed [1]byte
	if count, err := missing.Read(closed[:]); count != 0 || !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("unknown port read = %d bytes, %v; want a closed connection without visitor bytes", count, err)
	}
	client := connect(15432)
	if _, err := client.Write([]byte("startup!")); err != nil {
		t.Fatal(err)
	}
	var response [5]byte
	if _, err := io.ReadFull(client, response[:]); err != nil || string(response[:]) != "ready" {
		t.Fatalf("database greeting = %q, %v", response, err)
	}
	got := ingressAwait(t, received)
	if got.Source != netip.MustParseAddrPort("198.51.100.3:40001") || got.Destination != netip.MustParseAddrPort("203.0.113.10:15432") {
		t.Fatalf("forwarded metadata = %+v", got)
	}
	if httpsLookups.Load() != 0 || backend.opens.Load() != 1 {
		t.Fatalf("https lookups = %d, backend opens = %d", httpsLookups.Load(), backend.opens.Load())
	}
	u := ingressAwait(t, usage.opened)
	_ = client.Close()
	ingressAwait(t, u.closed)
	if u.publicURLID != "public_url_db" || u.publishRunNumber != 2 || u.ingressBytes != 8 || u.egressBytes != 5 {
		t.Fatalf("database usage = %+v", u)
	}
}

func TestIngressDatabasePortForwardsServerFirstGreeting(t *testing.T) {
	a, b := net.Pipe()
	ownIngressConn(t, a)
	ownIngressConn(t, b)
	backend := &rawVisitorBackend{connection: a}
	ingressWorker(t, func() { _ = a.Close(); _ = b.Close() }, func() error {
		defer b.Close()
		header, _, err := proxyproto.Decode(b)
		if err != nil {
			return err
		}
		if header.Destination.Port() != 3306 {
			t.Errorf("forwarded destination port = %d", header.Destination.Port())
		}
		_, err = b.Write([]byte("mysql-greeting"))
		return err
	})
	_, address := startIngress(t, Config{
		RequireProxyHeader: true,
		LookupPort: func(port uint16) (PublicURL, LookupReason) {
			if port != 3306 {
				return PublicURL{}, "missing"
			}
			return PublicURL{ID: "public_url_mysql", PublishRunNumber: 1, PublicPort: testPublicPort(3306),
				AllowAll: true, Backends: []routebackend.Backend{backend}}, ""
		},
	})
	client, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	ownIngressConn(t, client)
	header, err := proxyproto.Encode(proxyproto.Header{
		Source:      netip.MustParseAddrPort("198.51.100.3:40001"),
		Destination: netip.MustParseAddrPort("203.0.113.10:3306"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(header); err != nil {
		t.Fatal(err)
	}
	var response [14]byte
	if _, err := io.ReadFull(client, response[:]); err != nil || string(response[:]) != "mysql-greeting" {
		t.Fatalf("server-first greeting = %q, %v", response, err)
	}
	if backend.opens.Load() != 1 {
		t.Fatalf("backend opens = %d", backend.opens.Load())
	}
}

func TestIngressDeniedSSHAndMismatchedTCPRoutesCloseBeforePublisher(t *testing.T) {
	a, b := net.Pipe()
	ownIngressConn(t, a)
	ownIngressConn(t, b)
	backend := &rawVisitorBackend{connection: a}
	usage := newUsageRecorder()
	var allow atomic.Bool
	lookup := func() PublicURL {
		return PublicURL{ID: "public_url_db", PublishRunNumber: 1, PublicPort: testPublicPort(5432),
			ServiceProtocol: "ssh", Backends: []routebackend.Backend{backend}, AllowAll: allow.Load()}
	}
	_, address := startIngress(t, Config{
		RequireProxyHeader: true, OpenUsage: usage.Open,
		Lookup: func(string) (PublicURL, LookupReason) { return lookup(), LookupCurrent },
		LookupPort: func(uint16) (PublicURL, LookupReason) {
			return lookup(), ""
		},
	})
	try := func(port uint16) {
		t.Helper()
		client, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		ownIngressConn(t, client)
		header, err := proxyproto.Encode(proxyproto.Header{
			Source:      netip.MustParseAddrPort("198.51.100.3:40001"),
			Destination: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.10"), port),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(header); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("rejected TCP connection read = %v, want EOF", err)
		}
	}
	try(5432)
	u := ingressAwait(t, usage.opened)
	ingressAwait(t, u.closed)
	if u.policyDenials != 1 || u.streams != 0 || backend.opens.Load() != 0 {
		t.Fatalf("denied TCP usage = %+v, opens = %d", u, backend.opens.Load())
	}
	allow.Store(true)
	try(15432)
	https := ingressClient(t, address, "db.example", "198.51.100.3:40001")
	if err := https.Handshake(); err == nil {
		t.Fatal("TCP public URL was forwarded through HTTPS hostname routing")
	}
	if backend.opens.Load() != 0 {
		t.Fatal("mismatched public port opened a backend")
	}
}

type pendingDatabaseBackend struct {
	connection        net.Conn
	pending, ordinary atomic.Int32
}

func (b *pendingDatabaseBackend) Open(context.Context, string) (net.Conn, error) {
	b.ordinary.Add(1)
	return nil, errors.New("ordinary backend opened for denied database")
}
func (b *pendingDatabaseBackend) OpenPending(context.Context, string) (net.Conn, error) {
	b.pending.Add(1)
	return b.connection, nil
}

func TestIngressDeniedDatabasesUseBoundedPendingPath(t *testing.T) {
	for _, protocol := range []string{"postgres", "mysql", "redis"} {
		t.Run(protocol, func(t *testing.T) {
			a, b := net.Pipe()
			ownIngressConn(t, a)
			ownIngressConn(t, b)
			backend := &pendingDatabaseBackend{connection: a}
			received := make(chan proxyproto.Header, 1)
			release := make(chan struct{})
			worker := ingressWorker(t, func() { _ = a.Close(); _ = b.Close() }, func() error {
				defer b.Close()
				header, replay, err := proxyproto.Decode(b)
				if err != nil {
					return err
				}
				var startup [8]byte
				if _, err := io.ReadFull(replay, startup[:]); err != nil {
					return err
				}
				if string(startup[:]) != "TLSstart" {
					return errors.New("pending TLS startup changed")
				}
				received <- header
				select {
				case <-release:
				case <-t.Context().Done():
				}
				_, err = b.Write([]byte("TLS"))
				return err
			})
			s, address := startIngress(t, Config{RequireProxyHeader: true, LookupPort: func(uint16) (PublicURL, LookupReason) {
				return PublicURL{ID: "database", PublishRunNumber: 1, AccessMode: "restricted", AllowAll: true, ServiceProtocol: protocol, PublicPort: testPublicPort(5432), Backends: []routebackend.Backend{backend}}, LookupCurrent
			}})
			client, err := net.Dial("tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			ownIngressConn(t, client)
			header, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("198.51.100.1:40001"), Destination: netip.MustParseAddrPort("192.0.2.1:5432")})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Write(append(header, []byte("TLSstart")...)); err != nil {
				t.Fatal(err)
			}
			metadata := ingressAwait(t, received)
			if metadata.Source.String() != "198.51.100.1:40001" || metadata.Destination.Port() != 5432 {
				t.Fatal(metadata)
			}
			if s.Load() != 0 || backend.ordinary.Load() != 0 || backend.pending.Load() != 1 {
				t.Fatal("pending database consumed ordinary admission")
			}
			close(release)
			var answer [3]byte
			if _, err := io.ReadFull(client, answer[:]); err != nil || string(answer[:]) != "TLS" {
				t.Fatal(string(answer[:]), err)
			}
			if err := ingressAwait(t, worker); err != nil {
				t.Fatal(err)
			}
		})
	}
}
