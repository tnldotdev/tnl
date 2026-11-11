package peer

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/pion/stun/v4"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func unitICEMux(t *testing.T) (*socketICEMux, *agentICEMux) {
	t.Helper()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := newSocketICEMux(packet)
	t.Cleanup(func() { _ = m.Close() })
	return m, &agentICEMux{socketICEMux: m, password: "unit ICE password"}
}

func unitICEConn(t *testing.T, m *agentICEMux, ufrag string) *icePacketRef {
	t.Helper()
	c, err := m.GetConn(ufrag, m.packet.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.(*icePacketRef)
}

func stunRequest(t *testing.T, username string) *stun.Message {
	t.Helper()
	m, err := stun.Build(stun.TransactionID, stun.BindingRequest, stun.NewUsername(username), stun.MessageIntegrity([]byte("unit ICE password")))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSocketICEBoundsAuthenticatedInboundSourcesBeforeDispatch(t *testing.T) {
	m, mux := unitICEMux(t)
	c := unitICEConn(t, mux, "bounded")
	request := stunRequest(t, "bounded:peer")
	for port := range 2 * tunnelv1.MaxConnectorPeerCandidates {
		remote := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(1000+port))
		forged := append([]byte(nil), request.Raw...)
		forged[len(forged)-1] ^= 1
		m.dispatch(forged, remote)
	}
	if len(c.session.remotes) != 0 || len(c.queue) != 0 {
		t.Fatal("forged checks consumed the inbound source budget")
	}
	for port := range 2 * tunnelv1.MaxConnectorPeerCandidates {
		remote := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(1000+port))
		m.dispatch(request.Raw, remote)
		if port < tunnelv1.MaxConnectorPeerCandidates {
			readICEPacket(t, c)
		} else if len(c.queue) != 0 {
			t.Fatal("overflow source reached pion before the address limit")
		}
	}
	if len(c.session.remotes) != tunnelv1.MaxConnectorPeerCandidates {
		t.Fatal("authenticated inbound sources escaped the address bound")
	}
	m.dispatch(request.Raw, netip.MustParseAddrPort("127.0.0.1:1000"))
	readICEPacket(t, c)
	other := unitICEConn(t, mux, "sibling")
	m.dispatch(stunRequest(t, "sibling:peer").Raw, netip.MustParseAddrPort("127.0.0.1:9000"))
	readICEPacket(t, other)
}

func TestSocketICEReplacementGatherRefreshesInterfaces(t *testing.T) {
	socket := socketFixture(t, t.Context(), "0.0.0.0:0")
	ip := netip.MustParseAddr("192.0.2.1")
	socket.mux.localAddresses = func() ([]netip.Addr, error) { return []netip.Addr{ip}, nil }
	first, candidates := gatherSocketAgent(t, t.Context(), socket, nil, false, nil)
	if len(candidates) != 1 || candidates[0].Address() != ip.String() {
		t.Fatal("first gathering did not use current interfaces", candidates)
	}
	if err := first.GracefulClose(); err != nil {
		t.Fatal(err)
	}
	ip = netip.MustParseAddr("192.0.2.2")
	_, candidates = gatherSocketAgent(t, t.Context(), socket, nil, false, nil)
	if len(candidates) != 1 || candidates[0].Address() != ip.String() {
		t.Fatal("replacement gathering retained the departed interface", candidates)
	}
}

func stunResponse(t *testing.T, request *stun.Message) []byte {
	t.Helper()
	m, err := stun.Build(stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess)
	if err != nil {
		t.Fatal(err)
	}
	return m.Raw
}

func readICEPacket(t *testing.T, c net.PacketConn) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	defer c.SetReadDeadline(time.Time{})
	var b [iceSocketPacketBytes]byte
	n, _, err := c.ReadFrom(b[:])
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), b[:n]...)
}

func TestSocketICEDispatchUsesUsernameAndTransactionNotRemoteAddress(t *testing.T) {
	m, mux := unitICEMux(t)
	left, right := unitICEConn(t, mux, "left"), unitICEConn(t, mux, "right")
	remote := netip.MustParseAddrPort("127.0.0.1:9")
	a, b := stunRequest(t, "peer:left"), stunRequest(t, "peer:right")
	for _, test := range []struct {
		conn    *icePacketRef
		request *stun.Message
	}{{left, a}, {right, b}} {
		if _, err := test.conn.WriteTo(test.request.Raw, net.UDPAddrFromAddrPort(remote)); err != nil {
			t.Fatal(err)
		}
	}
	// both agents have written to this exact address. inbound requests must
	// follow their username, not the most recent writer's association.
	m.dispatch(stunRequest(t, "left:peer").Raw, remote)
	m.dispatch(stunRequest(t, "right:peer").Raw, remote)
	if len(left.queue) != 1 || len(right.queue) != 1 {
		t.Fatal("shared remote overwrote username dispatch")
	}
	readICEPacket(t, left)
	readICEPacket(t, right)
	m.dispatch(stunResponse(t, a), netip.MustParseAddrPort("127.0.0.1:10"))
	m.dispatch(stunResponse(t, stunRequest(t, "peer:left")), remote)
	m.dispatch(stunRequest(t, "unknown:peer").Raw, remote)
	if len(left.queue)+len(right.queue) != 0 {
		t.Fatal("unmatched source, transaction or username was dispatched")
	}
	m.dispatch(stunResponse(t, b), remote)
	m.dispatch(stunResponse(t, a), remote)
	if len(left.queue) != 1 || len(right.queue) != 1 {
		t.Fatal("response did not follow its owning transaction")
	}
	readICEPacket(t, left)
	readICEPacket(t, right)
	_ = left.Close()
	replacement := unitICEConn(t, mux, "left")
	m.dispatch(stunResponse(t, a), remote)
	m.dispatch(stunResponse(t, b), remote)
	if len(replacement.queue) != 0 || len(right.queue) != 1 {
		t.Fatal("agent close retained old transaction or removed sibling state")
	}
	_ = left.Close()
	m.dispatch(stunRequest(t, "left:peer").Raw, remote)
	if len(replacement.queue) != 1 {
		t.Fatal("old close removed replacement")
	}
	if _, err := replacement.WriteTo(b.Raw, net.UDPAddrFromAddrPort(remote)); !errors.Is(err, ErrConfiguration) {
		t.Fatal("a sibling stole an outstanding transaction", err)
	}
}

func TestSocketICEBoundsQueuesTransactionsRemotesAndSessions(t *testing.T) {
	m, mux := unitICEMux(t)
	c := unitICEConn(t, mux, "bounded")
	remote := netip.MustParseAddrPort("127.0.0.1:9")
	request := stunRequest(t, "bounded:peer")
	for range iceSocketQueue * 4 {
		m.dispatch(request.Raw, remote)
	}
	if len(c.queue) != iceSocketQueue {
		t.Fatal("ICE input queue is not bounded")
	}
	oldest := stunRequest(t, "peer:bounded")
	if _, err := c.WriteTo(oldest.Raw, net.UDPAddrFromAddrPort(remote)); err != nil {
		t.Fatal(err)
	}
	for range iceSocketTransactions - 1 {
		request = stunRequest(t, "peer:bounded")
		if _, err := c.WriteTo(request.Raw, net.UDPAddrFromAddrPort(remote)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.WriteTo(stunRequest(t, "peer:bounded").Raw, net.UDPAddrFromAddrPort(remote)); err != nil {
		t.Fatal("dispatch capacity prevented a later connectivity check", err)
	}
	if len(m.transactions) != iceSocketTransactions || len(c.session.transactions) != iceSocketTransactions {
		t.Fatal("unbounded outstanding STUN transactions")
	}
	for len(c.queue) > 0 {
		readICEPacket(t, c)
	}
	m.dispatch(stunResponse(t, oldest), remote)
	if len(c.queue) != 0 {
		t.Fatal("evicted transaction dispatched an old response")
	}
	for key, tx := range m.transactions {
		tx.expires = time.Now().Add(-time.Second)
		m.transactions[key] = tx
	}
	m.dispatch(stunResponse(t, request), remote)
	if len(c.queue) != 0 {
		t.Fatal("expired transaction dispatched a late response")
	}
	if _, err := c.WriteTo(stunRequest(t, "peer:bounded").Raw, net.UDPAddrFromAddrPort(remote)); err != nil {
		t.Fatal(err)
	}
	if len(m.transactions) > iceSocketTransactions {
		t.Fatal("expired transactions escaped the bounded ring")
	}
	// response writes also associate peer-reflexive addresses; cap them without
	// allocating a transaction for an inbound, unauthenticated packet.
	response := stunResponse(t, request)
	for port := 10; port < 9+tunnelv1.MaxConnectorPeerCandidates; port++ {
		if _, err := c.WriteTo(response, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.WriteTo(response, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("unbounded remote associations", err)
	}
	for i := range iceSocketSessions - 1 {
		unitICEConn(t, mux, "session-"+strconv.Itoa(i))
	}
	if _, err := mux.GetConn("overflow", m.packet.LocalAddr()); !errors.Is(err, ErrConfiguration) {
		t.Fatal("unbounded ICE sessions", err)
	}
	_ = c.Close()
	if len(c.queue) != 0 || c.session.queued != 0 || len(c.session.remotes) != 0 || len(m.transactions) != 0 {
		t.Fatal("closed agent retained queues or transaction state")
	}
	unitICEConn(t, mux, "replacement")
}

func TestSocketICEAuthenticatedPacketsKeepSiblingQueuesSeparate(t *testing.T) {
	m, _ := unitICEMux(t)
	// the real envelope belongs to the attempt owner. this fixture proves the
	// socket invokes its authentication predicate without owning that format.
	key := []byte("left attempt key")
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("packet"))
	frame := append([]byte("packet"), mac.Sum(nil)...)
	filter := func(key []byte) func([]byte) bool {
		return func(b []byte) bool {
			if len(b) < sha256.Size {
				return false
			}
			payload, tag := b[:len(b)-sha256.Size], b[len(b)-sha256.Size:]
			mac := hmac.New(sha256.New, key)
			_, _ = mac.Write(payload)
			return hmac.Equal(tag, mac.Sum(nil))
		}
	}
	left := unitICEConn(t, &agentICEMux{socketICEMux: m, acceptPacket: filter(key)}, "left")
	right := unitICEConn(t, &agentICEMux{socketICEMux: m, acceptPacket: filter([]byte("right attempt key"))}, "right")
	remote := netip.MustParseAddrPort("127.0.0.1:9")
	left.session.remotes[remote], right.session.remotes[remote] = left.icePacketConn, right.icePacketConn
	m.dispatch(frame, remote)
	if len(left.queue) != 1 || len(right.queue) != 0 {
		t.Fatal("authenticated packet reached a sibling ICE agent")
	}
	frame[len(frame)-1] ^= 1
	m.dispatch(frame, remote)
	if len(left.queue) != 1 || len(right.queue) != 0 {
		t.Fatal("forged packet reached an ICE agent")
	}
}

func TestSocketICEApplicationDispatchRequiresOneMatchingAgent(t *testing.T) {
	accept := func([]byte) bool { return true }
	reject := func([]byte) bool { return false }
	for _, test := range []struct {
		name    string
		filters [2]func([]byte) bool
		want    [2]int
	}{
		{"raw overlap", [2]func([]byte) bool{nil, nil}, [2]int{}},
		{"filtered overlap", [2]func([]byte) bool{accept, accept}, [2]int{}},
		{"raw and filtered overlap", [2]func([]byte) bool{nil, accept}, [2]int{}},
		{"unique raw", [2]func([]byte) bool{nil, reject}, [2]int{1, 0}},
		{"unique filtered", [2]func([]byte) bool{reject, accept}, [2]int{0, 1}},
		{"no match", [2]func([]byte) bool{reject, reject}, [2]int{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, _ := unitICEMux(t)
			remote := netip.MustParseAddrPort("127.0.0.1:9")
			var conns [2]*icePacketRef
			for i, filter := range test.filters {
				conns[i] = unitICEConn(t, &agentICEMux{socketICEMux: m, acceptPacket: filter}, strconv.Itoa(i))
				conns[i].session.remotes[remote] = conns[i].icePacketConn
			}
			m.dispatch([]byte("application packet"), remote)
			for i, c := range conns {
				if len(c.queue) != test.want[i] || c.session.queued != test.want[i] {
					t.Fatalf("agent %d queued %d packets (%d accounted), want %d", i, len(c.queue), c.session.queued, test.want[i])
				}
			}
			if test.want == [2]int{} {
				delete(conns[1].session.remotes, remote)
				if test.filters[0] == nil || test.filters[0]([]byte("application packet")) {
					m.dispatch([]byte("application packet"), remote)
					if len(conns[0].queue) != 1 || len(conns[1].queue) != 0 {
						t.Fatal("ambiguous dispatch changed the remaining agent's lifetime")
					}
				}
			}
		})
	}
}

func TestSocketICELocalCandidateDispatchAndAggregateQueueStayBounded(t *testing.T) {
	m, mux := unitICEMux(t)
	host := unitICEConn(t, mux, "candidates")
	otherConn, err := mux.GetConnForURL("candidates", "stun:127.0.0.1:9", m.packet.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	other := otherConn.(*icePacketRef)
	t.Cleanup(func() { _ = other.Close() })
	if other.icePacketConn == host.icePacketConn {
		t.Fatal("distinct local candidates share a competing reader")
	}
	remote := netip.MustParseAddrPort("127.0.0.1:9")
	first, second := stunRequest(t, "peer:candidates"), stunRequest(t, "peer:candidates")
	for _, send := range []struct {
		conn    *icePacketRef
		request *stun.Message
	}{{host, first}, {other, second}} {
		if _, err := send.conn.WriteTo(send.request.Raw, net.UDPAddrFromAddrPort(remote)); err != nil {
			t.Fatal(err)
		}
	}
	m.dispatch(stunRequest(t, "candidates:peer").Raw, remote)
	m.dispatch(stunResponse(t, second), remote)
	if len(host.queue) != 1 || len(other.queue) != 1 {
		t.Fatal("candidate writes stole request affinity or response ownership")
	}
	readICEPacket(t, host)
	readICEPacket(t, other)
	for i := range iceSocketQueue * 2 {
		m.dispatch(stunRequest(t, "candidates:peer").Raw, netip.AddrPortFrom(remote.Addr(), uint16(100+i%(tunnelv1.MaxConnectorPeerCandidates-1))))
	}
	if len(host.session.remotes) != tunnelv1.MaxConnectorPeerCandidates || host.session.queued != iceSocketQueue || len(host.queue)+len(other.queue) != iceSocketQueue {
		t.Fatal("candidate fanout escaped the session's bounds")
	}
	for i := range tunnelv1.MaxConnectorPeerCandidates - 2 {
		c, err := mux.GetConnForURL("candidates", "stun:127.0.0.1:"+strconv.Itoa(100+i), m.packet.LocalAddr())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
	}
	if _, err := mux.GetConnForURL("candidates", "overflow", m.packet.LocalAddr()); !errors.Is(err, ErrConfiguration) {
		t.Fatal("unbounded local candidate handles", err)
	}
	_ = host.Close()
	if other.closed || host.session.queued != 0 {
		t.Fatal("local candidate close affected another candidate or retained queued packets")
	}
}

func TestSocketICECandidateReferencesAndDeadlinesAreLocal(t *testing.T) {
	m, mux := unitICEMux(t)
	host := unitICEConn(t, mux, "shared")
	srflx, err := mux.GetConn("shared", m.packet.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer srflx.Close()
	_ = host.Close()
	if host.closed {
		t.Fatal("closing one candidate closed sibling candidate input")
	}
	_ = srflx.SetReadDeadline(time.Now())
	if _, _, err := srflx.ReadFrom(make([]byte, 2048)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("logical read deadline did not interrupt", err)
	}
	_ = srflx.SetWriteDeadline(time.Now())
	if _, err := srflx.WriteTo([]byte{1}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("logical write deadline was ignored", err)
	}
	other := unitICEConn(t, mux, "other")
	if _, err := other.WriteTo([]byte{1}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); err != nil {
		t.Fatal("logical deadline affected sibling", err)
	}
	_ = srflx.Close()
	if !host.closed {
		t.Fatal("last candidate did not release agent input")
	}
}

func TestSocketICECandidateReferencesAreBounded(t *testing.T) {
	m, mux := unitICEMux(t)
	var refs []net.PacketConn
	for range tunnelv1.MaxConnectorPeerCandidates {
		c, err := mux.GetConn("same", m.packet.LocalAddr())
		if err != nil {
			t.Fatal(err)
		}
		refs = append(refs, c)
		t.Cleanup(func() { _ = c.Close() })
	}
	if _, err := mux.GetConn("same", m.packet.LocalAddr()); !errors.Is(err, ErrConfiguration) {
		t.Fatal("repeated candidate references escaped the session bound", err)
	}
	_ = refs[0].Close()
	unitICEConn(t, mux, "same")
	if err := mux.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := refs[1].WriteTo([]byte{1}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); err != nil {
		t.Fatal("closing an agent's borrowed mux closed the socket", err)
	}
}

func TestSocketICEConcurrentReadAndCloseKeepQueueAccounting(t *testing.T) {
	for range 32 {
		m, mux := unitICEMux(t)
		c := unitICEConn(t, mux, "reader")
		remote := netip.MustParseAddrPort("127.0.0.1:9")
		c.session.remotes[remote] = c.icePacketConn
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(func() {
				var b [2048]byte
				for {
					if _, _, err := c.ReadFrom(b[:]); err != nil {
						return
					}
				}
			})
		}
		for range 128 {
			m.dispatch([]byte("packet"), remote)
		}
		_ = c.Close()
		wg.Wait()
		if c.session.queued != 0 || len(c.queue) != 0 {
			t.Fatal("closed reader retained queued packet accounting")
		}
	}
}

func TestSocketICEPacketBoundsAndDeadlinesPreservePackets(t *testing.T) {
	m, mux := unitICEMux(t)
	c := unitICEConn(t, mux, "reader")
	remote := netip.MustParseAddrPort("127.0.0.1:9")
	c.session.remotes[remote] = c.icePacketConn
	packet := bytes.Repeat([]byte{1}, iceSocketPacketBytes)
	m.dispatch(packet, remote)
	m.dispatch(append(packet, 1), remote)
	if got := readICEPacket(t, c); !bytes.Equal(got, packet) || len(c.queue) != 0 {
		t.Fatal("packet size bound truncated or admitted an oversized packet")
	}
	m.dispatch(packet, remote)
	if _, _, err := c.ReadFrom(make([]byte, 1)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal("short reader silently truncated a packet", err)
	}
	result := make(chan error, 1)
	go func() { _, _, err := c.ReadFrom(packet); result <- err }()
	_ = c.SetReadDeadline(time.Now())
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("updating a deadline left a logical read blocked")
	}
	for _, addr := range []net.Addr{&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, &net.UDPAddr{Port: 9}, &net.UDPAddr{IP: net.IPv4zero, Port: 9}, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 1), Port: 9}} {
		if _, err := c.WriteTo([]byte{1}, addr); !errors.Is(err, ErrConfiguration) {
			t.Fatal("accepted non-IP or non-unicast UDP candidate", addr, err)
		}
	}
	if _, err := c.WriteTo(append(packet, 1), net.UDPAddrFromAddrPort(remote)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal("oversized write was admitted", err)
	}
}

func TestSocketICEParentCancellationInterruptsLogicalReads(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	socket, err := ListenSocket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	c, err := (&agentICEMux{socketICEMux: socket.mux}).GetConn("canceled", socket.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, _, err := c.ReadFrom(make([]byte, 2048)); result <- err }()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("parent cancellation left an ICE reader blocked")
	}
	select {
	case <-socket.mux.done:
	case <-time.After(time.Second):
		t.Fatal("socket dispatcher did not join")
	}
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := socket.NewICE(nil, true); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed socket admitted a new agent", err)
	}
}

func TestSocketICEDiscoveryPadsOnlyPublicBindingRequests(t *testing.T) {
	for _, fingerprint := range []bool{false, true} {
		t.Run(strconv.FormatBool(fingerprint), func(t *testing.T) {
			m, mux := unitICEMux(t)
			c := newICEPacketConn(m, "", nil)
			m.discoveryConn = c
			defer c.Close()
			remote, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer remote.Close()
			setters := []stun.Setter{stun.TransactionID, stun.BindingRequest}
			if fingerprint {
				setters = append(setters, stun.Fingerprint)
			}
			request, err := stun.Build(setters...)
			if err != nil {
				t.Fatal(err)
			}
			if n, err := c.WriteTo(request.Raw, remote.LocalAddr()); err != nil || n != len(request.Raw) {
				t.Fatal("padding changed the caller's write count", n, err)
			}
			wire := readICEPacket(t, remote)
			padded := &stun.Message{Raw: wire}
			if err := padded.Decode(); err != nil || len(wire) != iceSocketSTUNBytes || padded.TransactionID != request.TransactionID || !padded.Contains(stun.AttrPadding) {
				t.Fatal("discovery padding changed the STUN transaction", len(wire), err)
			}
			if fingerprint {
				if err := stun.Fingerprint.Check(padded); err != nil {
					t.Fatal("padding invalidated the fingerprint", err)
				}
			}
			if len(request.Raw) != 20+map[bool]int{false: 0, true: 8}[fingerprint] {
				t.Fatal("padding modified the caller's request")
			}
			host := unitICEConn(t, mux, "checks")
			check, err := stun.Build(setters...)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := host.WriteTo(check.Raw, remote.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			if got := readICEPacket(t, remote); !bytes.Equal(got, check.Raw) {
				t.Fatal("public discovery padding changed ICE checks")
			}
			response := stunResponse(t, request)
			if _, err := c.WriteTo(response, remote.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			if got := readICEPacket(t, remote); !bytes.Equal(got, response) {
				t.Fatal("public discovery padding changed responses")
			}
		})
	}
}

func TestSocketICEDiscoveryCacheAndConcurrentQueriesAreBounded(t *testing.T) {
	socket := socketFixture(t, t.Context(), "127.0.0.1:0")
	m := socket.mux
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	if _, err := m.GetXORMappedAddrContext(ctx, remote, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	m.mu.Lock()
	if len(m.servers) != 0 || m.discoveries != 0 {
		t.Fatal("canceled query retained discovery state")
	}
	for port := 1; port <= iceSocketServers; port++ {
		m.servers[netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))] = struct{}{}
	}
	m.mu.Unlock()
	if _, err := m.GetXORMappedAddrContext(t.Context(), &net.UDPAddr{IP: remote.IP, Port: iceSocketServers + 1}, time.Second); !errors.Is(err, ErrConfiguration) {
		t.Fatal("unbounded discovery cache", err)
	}
	m.mu.Lock()
	m.discoveries = iceSocketServers
	m.mu.Unlock()
	if _, err := m.GetXORMappedAddrContext(t.Context(), remote, time.Second); !errors.Is(err, ErrConfiguration) {
		t.Fatal("unbounded concurrent discovery transactions", err)
	}
	m.mu.Lock()
	m.discoveries = 0
	m.mu.Unlock()
}
