package ingress

import (
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	router "github.com/tnldotdev/tnl/internal/ingress/clienthello"
)

func TestPublicURLConnectionClassUsesProcessCapacity(t *testing.T) {
	for _, limit := range []int{1, 4, 5} {
		server, _ := startIngress(t, Config{MaxConnections: limit})
		var releases []func()
		for range limit {
			release, rejected := server.admitClass(visitorConnection, "url_one")
			if release == nil {
				t.Fatalf("first public URL rejected: %s", rejected)
			}
			releases = append(releases, release)
		}
		if release, rejected := server.admitClass(visitorConnection, "url_two"); release != nil || rejected != "public_connections" {
			t.Fatalf("exceeded process limit: %s", rejected)
		}
		for _, release := range releases {
			release()
			release()
		}
		if len(server.byPublicURL) != 0 || server.Load() != 0 {
			t.Fatal("public URL accounting retained closed connections")
		}
	}
}

func TestClientHelloCapacityAndTimeoutRelease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &Server{config: Config{MaxClientHelloConnections: 1}, connections: make(map[net.Conn]struct{})}
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		connection := &testAddressConn{Conn: a}
		if !server.admit(connection) {
			t.Fatal("first inspection rejected")
		}
		if server.admit(b) {
			t.Fatal("inspection capacity exceeded")
		}
		done := make(chan error, 1)
		go func() {
			defer server.active.Done()
			defer server.release(connection)
			defer server.finishInspection()
			done <- server.handle(connection, func() { t.Error("stalled ClientHello finished inspection") })
		}()
		synctest.Wait()
		time.Sleep(router.ClientHelloReadTimeout)
		synctest.Wait()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if server.pending != 0 || len(server.connections) != 0 {
			t.Fatal("timed-out inspection retained capacity")
		}
		if !server.admit(b) {
			t.Fatal("inspection slot not reusable after timeout")
		}
		server.finishInspection()
		server.release(b)
		server.active.Done()
	})
}

type testAddressConn struct{ net.Conn }

func (*testAddressConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}
func (*testAddressConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
}

func TestFailedHandoffReleasesCapacity(t *testing.T) {
	server, _ := startIngress(t, Config{MaxRelayConnections: 1})
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	for range 2 {
		called := false
		if server.handoff(a, netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort("127.0.0.1:443"), router.ClientHello{}, relayConnection,
			func(net.Conn) bool { called = true; return false }) || !called {
			t.Fatal("failed handoff retained a slot")
		}
	}
}
