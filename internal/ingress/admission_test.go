package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
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
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestActiveChallengeDoesNotConsumeVisitorBudget(t *testing.T) {
	backend := newTLSBackend(t, "acme-tls/1")
	var active atomic.Bool
	active.Store(true)
	var ordinaryLookups atomic.Int32
	config := Config{
		MaxConnections: 1,
		Lookup: func(string) (PublicURL, LookupReason) {
			ordinaryLookups.Add(1)
			return PublicURL{}, "not_found"
		},
		LookupChallenge: func(host string) ([]routebackend.Backend, LookupReason) {
			if host != "route.example" || !active.Load() {
				return nil, "missing"
			}
			return []routebackend.Backend{backend}, ""
		},
	}
	server, address := startIngress(t, config)
	ordinary := ingressClient(t, address, "route.example", "")
	_ = ordinary.Handshake()
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
	active.Store(false) // simulate a tombstone or expired challenge projection.
	stale := ingressClient(t, address, "route.example", "", "acme-tls/1")
	if err := stale.Handshake(); err == nil {
		t.Fatal("stale challenge was forwarded")
	}
	_ = stale.Close()
	mixed := ingressClient(t, address, "route.example", "", "h2", "acme-tls/1")
	if err := mixed.Handshake(); err == nil {
		t.Fatal("mixed ALPN reached a backend")
	}
	_ = mixed.Close()
	if backend.opens.Load() != 1 || ordinaryLookups.Load() != 2 || server.Load() != 1 {
		t.Fatalf("opens=%d lookups=%d visitor load=%d", backend.opens.Load(), ordinaryLookups.Load(), server.Load())
	}
}

func TestChallengeCapacityIsBoundedAndIndependent(t *testing.T) {
	server, _ := startIngress(t, Config{MaxConnections: 1,
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

func TestPublicURLConnectionLimitTracksHalfOfIngressCapacity(t *testing.T) {
	for _, test := range []struct{ ingressLimit, perURL int }{{1, 1}, {4, 2}, {5, 2}} {
		server, _ := startIngress(t, Config{MaxConnections: test.ingressLimit})
		var releases []func()
		for range test.perURL {
			release, rejected := server.admitClass(visitorConnection, "url_one")
			if release == nil {
				t.Fatalf("ingress %d: first public URL rejected: %s", test.ingressLimit, rejected)
			}
			releases = append(releases, release)
		}
		if release, rejected := server.admitClass(visitorConnection, "url_one"); release != nil || rejected != "public_url_connections" {
			t.Fatalf("ingress %d: exceeded public URL limit: %s", test.ingressLimit, rejected)
		}
		if test.ingressLimit > test.perURL {
			release, rejected := server.admitClass(visitorConnection, "url_two")
			if release == nil {
				t.Fatalf("ingress %d: another public URL rejected: %s", test.ingressLimit, rejected)
			}
			release()
		}
		for _, release := range releases {
			release()
		}
		if len(server.byPublicURL) != 0 || server.Load() != 0 {
			t.Fatal("public URL accounting retained closed connections")
		}
	}
}

func TestAuthorizedVisitorsLeavePendingCapacityWithoutReplayingAdmission(t *testing.T) {
	server, _ := startIngress(t, Config{MaxConnections: 40, Lookup: func(host string) (PublicURL, LookupReason) {
		if host == "app.example" {
			return PublicURL{ID: "url_1", PublishRunNumber: 2}, LookupCurrent
		}
		return PublicURL{}, LookupMissing
	}})
	for index := range 9 {
		release, rejected := server.admitClass(deniedConnection, "url_1")
		if release == nil {
			t.Fatalf("pending visitor %d: %s", index, rejected)
		}
		ticket := &classTicket{release: release, deadline: time.Now().Add(time.Minute)}
		id := fmt.Sprintf("visitor_%d", index)
		unregister := server.registerPendingVisitor(id, &pendingVisitorState{ticket: ticket, urlID: "url_1", run: 2,
			hostname: "app.example", deadline: ticket.deadline})
		t.Cleanup(func() { unregister(); ticket.close() })
		result := server.PromotePendingAdmission(t.Context(), tunnelv1.AdmissionHeader{
			ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.IngressAdmissionStream,
			VisitorConnectionID: id, PublicURLID: "url_1", PublishRunNumber: 2,
		})
		if result.Type != tunnelv1.StreamAccepted || result.Code != "" {
			t.Fatalf("authorized visitor %d = %+v", index, result)
		}
		if replay := server.PromotePendingAdmission(t.Context(), tunnelv1.AdmissionHeader{
			Kind: tunnelv1.IngressAdmissionStream, VisitorConnectionID: id, PublicURLID: "url_1", PublishRunNumber: 2,
		}); replay.Type != tunnelv1.StreamRejected {
			t.Fatalf("replayed decision = %+v", replay)
		}
	}
	server.mu.Lock()
	pendingCount, ordinaryCount, urlCount := server.admitted[deniedConnection], server.admitted[visitorConnection], server.byPublicURL["url_1"]
	server.mu.Unlock()
	if pendingCount != 0 || ordinaryCount != 9 || urlCount != 9 {
		t.Fatalf("promoted class counts = pending:%d ordinary:%d url:%d", pendingCount, ordinaryCount, urlCount)
	}
}

func TestPendingVisitorCannotUseOrdinaryCapacityWithoutItsToken(t *testing.T) {
	server, _ := startIngress(t, Config{MaxConnections: 1, Lookup: func(string) (PublicURL, LookupReason) {
		return PublicURL{ID: "url_1", PublishRunNumber: 2}, LookupCurrent
	}})
	ordinary, rejected := server.admitClass(visitorConnection, "url_1")
	if ordinary == nil {
		t.Fatal(rejected)
	}
	defer ordinary()
	release, rejected := server.admitClass(deniedConnection, "url_1")
	if release == nil {
		t.Fatal(rejected)
	}
	ticket := &classTicket{release: release, deadline: time.Now().Add(time.Minute)}
	defer ticket.close()
	unregister := server.registerPendingVisitor("visitor_1", &pendingVisitorState{ticket: ticket, urlID: "url_1", run: 2,
		hostname: "app.example", deadline: ticket.deadline})
	defer unregister()
	result := server.PromotePendingAdmission(t.Context(), tunnelv1.AdmissionHeader{
		Kind: tunnelv1.IngressAdmissionStream, VisitorConnectionID: "visitor_1", PublicURLID: "url_1", PublishRunNumber: 2,
	})
	if result.Type != tunnelv1.StreamRejected || result.Code != tunnelv1.CapacityExceeded || ticket.isPromoted() {
		t.Fatalf("full ingress admitted pending visitor: %+v", result)
	}
	server.mu.Lock()
	pendingCount, ordinaryCount := server.admitted[deniedConnection], server.admitted[visitorConnection]
	server.mu.Unlock()
	if pendingCount != 1 || ordinaryCount != 1 {
		t.Fatalf("failed transfer changed capacities: pending=%d ordinary=%d", pendingCount, ordinaryCount)
	}
	if err := ticket.pendingBytesAllowed(DefaultPendingConnectionBytes); err != nil {
		t.Fatal(err)
	}
	if err := ticket.pendingBytesAllowed(1); err == nil {
		t.Fatal("pending visitor exceeded the bounded byte budget")
	}
}

func TestPendingVisitorUsesCurrentPublicURLCapacity(t *testing.T) {
	var limits TrafficLimits
	server, _ := startIngress(t, Config{MaxConnections: 40, Lookup: func(string) (PublicURL, LookupReason) {
		return PublicURL{ID: "url_1", PublishRunNumber: 2, Traffic: &limits}, LookupCurrent
	}})
	limits = server.config.Traffic.Default
	limits.Connections = 1
	ordinary, rejected := server.admitClass(visitorConnection, "url_1")
	if ordinary == nil {
		t.Fatal(rejected)
	}
	defer ordinary()
	release, rejected := server.admitClass(deniedConnection, "url_1")
	if release == nil {
		t.Fatal(rejected)
	}
	ticket := &classTicket{release: release, deadline: time.Now().Add(time.Minute)}
	defer ticket.close()
	unregister := server.registerPendingVisitor("visitor_1", &pendingVisitorState{ticket: ticket, urlID: "url_1", run: 2,
		hostname: "app.example", deadline: ticket.deadline})
	defer unregister()
	result := server.PromotePendingAdmission(t.Context(), tunnelv1.AdmissionHeader{
		Kind: tunnelv1.IngressAdmissionStream, VisitorConnectionID: "visitor_1", PublicURLID: "url_1", PublishRunNumber: 2,
	})
	if result.Type != tunnelv1.StreamRejected || result.Code != tunnelv1.CapacityExceeded || ticket.isPromoted() {
		t.Fatalf("current public URL limit admitted pending visitor: %+v", result)
	}
}

func TestPendingSourceCapacityAndAttemptRatesAreIndependent(t *testing.T) {
	if pendingSourceNetwork(netip.MustParseAddr("2001:db8:1::1")) != pendingSourceNetwork(netip.MustParseAddr("2001:db8:1::2")) ||
		pendingSourceNetwork(netip.MustParseAddr("2001:db8:1::1")) == pendingSourceNetwork(netip.MustParseAddr("2001:db8:2::1")) {
		t.Fatal("pending IPv6 source capacity does not use /64 networks")
	}
	server, _ := startIngress(t, Config{MaxConnections: 40, MaxPendingSourceConnections: 2})
	first, reason := server.admitPending("url_1", "192.0.2.10", server.config.Traffic.Default.Connections)
	if first == nil {
		t.Fatal(reason)
	}
	defer first()
	second, reason := server.admitPending("url_1", "192.0.2.10", server.config.Traffic.Default.Connections)
	if second == nil {
		t.Fatal(reason)
	}
	defer second()
	if third, reason := server.admitPending("url_1", "192.0.2.10", server.config.Traffic.Default.Connections); third != nil || reason != "pending_source_connections" {
		t.Fatalf("source exhausted pending capacity: %s", reason)
	}
	other, reason := server.admitPending("url_1", "192.0.2.11", server.config.Traffic.Default.Connections)
	if other == nil {
		t.Fatalf("unrelated source was blocked: %s", reason)
	}
	other()
	first()
	reopened, reason := server.admitPending("url_1", "192.0.2.10", server.config.Traffic.Default.Connections)
	if reopened == nil {
		t.Fatalf("released source slot remained full: %s", reason)
	}
	reopened()
	key := trafficKey{url: "url_1", run: 2}
	source := netip.MustParseAddr("192.0.2.10")
	if allowed, _ := server.traffic.allowPendingAttempt(key, source, 1, 1, 1, 1); !allowed {
		t.Fatal("first pending attempt was refused")
	}
	if allowed, reason := server.traffic.allowPendingAttempt(key, source, 1, 1, 1, 1); allowed || reason != "pending_public_url_rate" {
		t.Fatalf("pending URL rate was not enforced: %s", reason)
	}
	if allowed, reason := server.traffic.allowPendingAttempt(trafficKey{url: "url_2", run: 2}, source, 1, 1, 1, 1); allowed || reason != "pending_source_rate" {
		t.Fatalf("pending source rate was not enforced across URLs: %s", reason)
	}
}

func TestClientHelloCapacityAndTimeoutRelease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := &Server{config: Config{MaxClientHelloConnections: 1}, connections: make(map[net.Conn]struct{})}
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		// address metadata is already provided, as it is after trusted PROXY
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
	config := Config{OpenTimeout: time.Minute, LookupChallenge: func(string) ([]routebackend.Backend, LookupReason) {
		return []routebackend.Backend{backend}, ""
	}}
	server, address := startIngress(t, config)
	client := ingressClient(t, address, "route.example", "", "acme-tls/1")
	done := ingressWorker(t, func() { _ = client.Close() }, client.Handshake)
	deadline := ingressAwait(t, backend.deadline)
	if deadline.IsZero() || time.Until(deadline) > challengeConnectionTimeout {
		t.Fatalf("challenge backend open not bounded by challenge deadline: %s", deadline)
	}
	// forced drain must cancel a pending challenge open just as it cancels a
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
		server, err := New(listener, Config{MaxConnections: 1,
			Lookup: func(string) (PublicURL, LookupReason) { return PublicURL{}, LookupNotFound },
			LookupChallenge: func(string) ([]routebackend.Backend, LookupReason) {
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
		client := tls.Client(clientSocket, &tls.Config{ServerName: "route.example", NextProtos: []string{"acme-tls/1"}, InsecureSkipVerify: true}) // self-signed fixture.
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
