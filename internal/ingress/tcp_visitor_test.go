package ingress

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/routebackend"
)

type rawVisitorBackend struct {
	connection net.Conn
	opens      atomic.Int32
}

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
		Lookup: func(string) (PublicURL, string) {
			httpsLookups.Add(1)
			return PublicURL{}, "missing"
		},
		LookupPort: func(port uint16) (PublicURL, string) {
			if port != 15432 {
				return PublicURL{}, "missing"
			}
			return PublicURL{ID: "public_url_db", PublishRunNumber: 2, PublicPort: 15432,
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
	if _, err := missing.Read(closed[:]); err != io.EOF {
		t.Fatalf("unknown port read = %v, want EOF", err)
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
		LookupPort: func(port uint16) (PublicURL, string) {
			if port != 3306 {
				return PublicURL{}, "missing"
			}
			return PublicURL{ID: "public_url_mysql", PublishRunNumber: 1, PublicPort: 3306,
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

func TestIngressDatabasePortRejectsDeniedAndMismatchedRoutes(t *testing.T) {
	a, b := net.Pipe()
	ownIngressConn(t, a)
	ownIngressConn(t, b)
	backend := &rawVisitorBackend{connection: a}
	usage := newUsageRecorder()
	var allow atomic.Bool
	lookup := func() PublicURL {
		return PublicURL{ID: "public_url_db", PublishRunNumber: 1, PublicPort: 5432,
			Backends: []routebackend.Backend{backend}, AllowAll: allow.Load()}
	}
	_, address := startIngress(t, Config{
		RequireProxyHeader: true, OpenUsage: usage.Open,
		Lookup: func(string) (PublicURL, string) { return lookup(), "" },
		LookupPort: func(uint16) (PublicURL, string) {
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
			t.Fatalf("rejected database connection read = %v, want EOF", err)
		}
	}
	try(5432)
	u := ingressAwait(t, usage.opened)
	ingressAwait(t, u.closed)
	if u.policyDenials != 1 || u.streams != 0 || backend.opens.Load() != 0 {
		t.Fatalf("denied database usage = %+v, opens = %d", u, backend.opens.Load())
	}
	allow.Store(true)
	try(15432)
	https := ingressClient(t, address, "db.example", "198.51.100.3:40001")
	if err := https.Handshake(); err == nil {
		t.Fatal("database URL was forwarded through HTTPS hostname routing")
	}
	if backend.opens.Load() != 0 {
		t.Fatal("mismatched public port opened a backend")
	}
}
