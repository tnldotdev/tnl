package peer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
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
	t.Cleanup(func() { _ = packet.Close() })
	m := &socketICEMux{packet: packet, conns: make(map[string]*iceSession), transactions: make(map[iceTransactionKey]iceTransaction), servers: make(map[netip.AddrPort]struct{})}
	return m, &agentICEMux{socketICEMux: m}
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
	m, err := stun.Build(stun.TransactionID, stun.BindingRequest, stun.NewUsername(username))
	if err != nil {
		t.Fatal(err)
	}
	return m
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
	var b [2048]byte
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
	// still follow their username, not the most recent writer's association.
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
	// a repeated close of an old reference cannot remove a replacement.
	_ = left.Close()
	m.dispatch(stunRequest(t, "left:peer").Raw, remote)
	if len(replacement.queue) != 1 {
		t.Fatal("old close removed replacement")
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
	// expiration permits a later check, but an old response must not reach it.
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
	for port := 10; port < 9+tunnelv1.MaxNativePeerCandidates; port++ {
		if _, err := c.WriteTo(response, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.WriteTo(response, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("unbounded remote associations", err)
	}
	for i := range iceSocketSessions - 1 {
		unitICEConn(t, mux, string(rune('A'+i)))
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

func TestSocketICENativePacketMACDispatchKeepsSiblingQueuesSeparate(t *testing.T) {
	m, _ := unitICEMux(t)
	left := unitICEConn(t, &agentICEMux{socketICEMux: m, acceptPacket: nativeICEPacketFilter(Config{Key: [32]byte{1}, Role: 1})}, "left")
	right := unitICEConn(t, &agentICEMux{socketICEMux: m, acceptPacket: nativeICEPacketFilter(Config{Key: [32]byte{2}, Role: 1})}, "right")
	remote := netip.MustParseAddrPort("127.0.0.1:9")
	left.session.remotes[remote], right.session.remotes[remote] = left.icePacketConn, right.icePacketConn
	sender := &Endpoint{config: Config{Key: [32]byte{1}}}
	sender.paths[Direct] = &path{queue: make(chan queuedFrame, 1)}
	sender.enqueue(Direct, tunnelv1.PeerPacket{Kind: tunnelv1.PeerProbe, Sequence: 1, Total: 16, Payload: make([]byte, 16)}, 0)
	frame := (<-sender.paths[Direct].queue).data
	m.dispatch(frame, remote)
	if len(left.queue) != 1 || len(right.queue) != 0 {
		t.Fatal("native packet reached a sibling ICE agent")
	}
	frame[len(frame)-1] ^= 1
	m.dispatch(frame, remote)
	if len(left.queue) != 1 || len(right.queue) != 0 {
		t.Fatal("forged native packet reached an ICE agent")
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
				// dropping ambiguity must not retire an agent or its sibling. once
				// only one association remains, the same packet has one recipient.
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
	// only engine writes may create a remote association. unauthenticated
	// requests cannot fill that state, and all candidates share one queue budget.
	for i := range iceSocketQueue * 2 {
		m.dispatch(stunRequest(t, "candidates:peer").Raw, netip.AddrPortFrom(remote.Addr(), uint16(100+i)))
	}
	if len(host.session.remotes) != 1 || host.session.queued != iceSocketQueue || len(host.queue)+len(other.queue) != iceSocketQueue {
		t.Fatal("candidate fanout escaped the session's bounds")
	}
	for i := range tunnelv1.MaxNativePeerCandidates - 2 {
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

func TestSocketICEParentCancellationInterruptsLogicalReads(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	socket, err := ListenSocket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	mux := any(socket.mux).(*socketICEMux)
	c, err := (&agentICEMux{socketICEMux: mux}).GetConn("canceled", socket.LocalAddr())
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
	case <-mux.done:
	case <-time.After(time.Second):
		t.Fatal("socket dispatcher did not join")
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
	if _, err := srflx.WriteTo([]byte{1}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); err == nil {
		t.Fatal("logical write deadline was ignored")
	}
	// a sibling still writes using the physical socket after those deadlines.
	other := unitICEConn(t, mux, "other")
	if _, err := other.WriteTo([]byte{1}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); err != nil {
		t.Fatal("logical deadline affected sibling", err)
	}
	_ = srflx.Close()
	if !host.closed {
		t.Fatal("last candidate did not release agent input")
	}
}
