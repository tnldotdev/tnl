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
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/routebackend"
	"github.com/tnldotdev/tnl/internal/router"
)

func TestActiveChallengeDoesNotConsumeVisitorBudget(t *testing.T) {
	backend := newTLSBackend(t, "acme-tls/1")
	var active atomic.Bool
	active.Store(true)
	var ordinaryLookups atomic.Int32
	config := Config{
		SourceConnectionRate: 0.000001, SourceConnectionBurst: 1,
		MaxConnections: 1, MaxRouteConnections: 1,
		Lookup: func(string) (Route, bool) {
			ordinaryLookups.Add(1)
			return Route{}, false
		},
		LookupChallenge: func(host string) ([]routebackend.Backend, string) {
			if host != "route.example" || !active.Load() {
				return nil, "missing"
			}
			return []routebackend.Backend{backend}, ""
		},
	}
	server, address := startIngress(t, config)
	ordinary := ingressClient(t, address, "route.example", "")
	_ = ordinary.Handshake() // Consume the single ordinary visitor token.
	_ = ordinary.Close()
	release, rejected := server.admitClass(visitorConnection, "busy-route")
	if release == nil {
		t.Fatal(rejected)
	}
	defer release()
	for _, host := range []string{"unknown.example", "other.route.example"} {
		fake := ingressClient(t, address, host, "", "acme-tls/1")
		if err := fake.Handshake(); err == nil {
			t.Fatal("unregistered challenge was forwarded")
		}
		_ = fake.Close()
	}
	client := ingressClient(t, address, "route.example", "", "acme-tls/1")
	exchangePing(t, client)
	if result := ingressAwait(t, backend.result); result.err != nil {
		t.Fatal(result.err)
	}
	active.Store(false) // Simulate a tombstone or expired challenge projection.
	stale := ingressClient(t, address, "route.example", "", "acme-tls/1")
	if err := stale.Handshake(); err == nil {
		t.Fatal("stale challenge was forwarded")
	}
	_ = stale.Close()
	mixed := ingressClient(t, address, "route.example", "", "h2", "acme-tls/1")
	if err := mixed.Handshake(); err == nil {
		t.Fatal("mixed ALPN bypassed visitor rate limiting")
	}
	_ = mixed.Close()
	if backend.opens.Load() != 1 || ordinaryLookups.Load() != 1 || server.Load() != 1 {
		t.Fatalf("opens=%d lookups=%d visitor load=%d", backend.opens.Load(), ordinaryLookups.Load(), server.Load())
	}
}

func TestChallengeCapacityIsBoundedAndIndependent(t *testing.T) {
	server, _ := startIngress(t, Config{MaxConnections: 1, MaxRouteConnections: 1,
		MaxChallengeConnections: 2, MaxHostnameChallengeConnections: 1,
		MaxControlConnections: 1, MaxRelayConnections: 1})
	first, rejected := server.admitClass(challengeConnection, "one.example")
	if first == nil {
		t.Fatal(rejected)
	}
	defer first()
	if release, reason := server.admitClass(challengeConnection, "one.example"); release != nil || reason != "challenge_hostname_connections" {
		t.Fatal("per-hostname challenge capacity was not enforced")
	}
	second, rejected := server.admitClass(challengeConnection, "two.example")
	if second == nil {
		t.Fatal(rejected)
	}
	defer second()
	if release, reason := server.admitClass(challengeConnection, "three.example"); release != nil || reason != "challenge_connections" {
		t.Fatal("global challenge capacity was not enforced")
	}
	for _, kind := range []connectionKind{visitorConnection, controlConnection, relayConnection} {
		release, reason := server.admitClass(kind, "one.example")
		if release == nil {
			t.Fatalf("challenge saturation consumed other capacity: %s", reason)
		}
		t.Cleanup(release)
	}
	first()
	first()
	reopened, rejected := server.admitClass(challengeConnection, "one.example")
	if reopened == nil {
		t.Fatalf("released challenge slot not reusable: %s", rejected)
	}
	reopened()
	second()
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.byChallenge) != 0 || server.admitted[challengeConnection] != 0 {
		t.Fatal("challenge counters/hostname entries leaked")
	}
}

func TestClientHelloCapacityAndTimeoutRelease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &Server{config: Config{MaxClientHelloConnections: 1}, connections: make(map[net.Conn]struct{})}
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		// Address metadata is already provided, as it is after trusted PROXY
		// decoding; the peer stalls without sending a ClientHello.
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
	server, _ := startIngress(t, Config{MaxControlConnections: 1})
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	for range 2 {
		called := false
		if server.handoff(a, netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort("127.0.0.1:443"), router.ClientHello{}, controlConnection,
			func(net.Conn) bool { called = true; return false }) || !called {
			t.Fatal("failed handoff retained a slot")
		}
	}
}

type challengeDeadlineBackend struct{ deadline chan time.Time }

func (b challengeDeadlineBackend) Open(ctx context.Context, _ string) (net.Conn, error) {
	deadline, _ := ctx.Deadline()
	b.deadline <- deadline
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestChallengeDeadlineAndForcedDrain(t *testing.T) {
	backend := challengeDeadlineBackend{deadline: make(chan time.Time, 1)}
	config := Config{OpenTimeout: time.Minute, LookupChallenge: func(string) ([]routebackend.Backend, string) {
		return []routebackend.Backend{backend}, ""
	}}
	server, address := startIngress(t, config)
	client := ingressClient(t, address, "route.example", "", "acme-tls/1")
	done := ingressWorker(t, func() { _ = client.Close() }, client.Handshake)
	deadline := ingressAwait(t, backend.deadline)
	if deadline.IsZero() || time.Until(deadline) > challengeConnectionTimeout {
		t.Fatalf("challenge backend open not bounded by challenge deadline: %s", deadline)
	}
	// Forced drain must cancel a pending challenge open just as it cancels a
	// visitor open, and every class counter must be released.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := server.Drain(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	_ = ingressAwait(t, done)
	server.active.Wait()
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.admitted[challengeConnection] != 0 || len(server.byChallenge) != 0 || server.pending != 0 {
		t.Fatal("drain retained challenge admission")
	}
}

func TestChallengeStreamDeadlineReleasesCapacity(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	certificate := testCertificate(t, "route.example")
	synctest.Test(t, func(t *testing.T) {
		public, clientSocket := net.Pipe()
		upstream, origin := net.Pipe()
		defer public.Close()
		defer clientSocket.Close()
		defer upstream.Close()
		defer origin.Close()
		server, err := New(listener, Config{MaxConnections: 1, MaxRouteConnections: 1,
			Lookup: func(string) (Route, bool) { return Route{}, false },
			LookupChallenge: func(string) ([]routebackend.Backend, string) {
				return []routebackend.Backend{singleBackend{upstream}}, ""
			}})
		if err != nil {
			t.Fatal(err)
		}
		defer server.cancelOpens()
		go func() {
			_, replay, err := proxyproto.Decode(origin)
			if err != nil {
				t.Error(err)
				return
			}
			tlsServer := tls.Server(&readerConn{Conn: origin, reader: replay}, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"acme-tls/1"}})
			_, _ = io.Copy(io.Discard, tlsServer)
		}()
		connection := &testAddressConn{Conn: public}
		if !server.admit(connection) {
			t.Fatal("inspection rejected")
		}
		done := make(chan error, 1)
		go func() {
			defer server.active.Done()
			defer server.release(connection)
			finish := sync.OnceFunc(server.finishInspection)
			defer finish()
			done <- server.handle(connection, finish)
		}()
		client := tls.Client(clientSocket, &tls.Config{ServerName: "route.example", NextProtos: []string{"acme-tls/1"}, InsecureSkipVerify: true}) // Self-signed fixture.
		if err := client.Handshake(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		server.mu.Lock()
		activeChallenges := server.admitted[challengeConnection]
		server.mu.Unlock()
		if activeChallenges != 1 {
			t.Fatal("challenge slot was released before stream close")
		}
		time.Sleep(challengeConnectionTimeout)
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("stalled challenge stream outlived its deadline")
		}
		server.mu.Lock()
		activeChallenges, challengeHostnames := server.admitted[challengeConnection], len(server.byChallenge)
		server.mu.Unlock()
		if activeChallenges != 0 || challengeHostnames != 0 {
			t.Fatal("expired challenge retained capacity")
		}
	})
}
