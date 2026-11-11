package peer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v4"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

// this fixture supplies mapping replies only. relay discovery policy stays with
// the relay owner; the socket test checks shared transport mechanics.
func serveSocketMappingFixture(t *testing.T, ctx context.Context, listener *muxsession.QUICListener) {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	packets := listener.NonQUICPackets(ctx)
	done := make(chan error, 1)
	go func() {
		var buffer [2048]byte
		for {
			n, remote, err := packets.ReadFrom(buffer[:])
			if err != nil {
				if ctx.Err() != nil {
					err = nil
				}
				done <- err
				return
			}
			request := &stun.Message{Raw: buffer[:n]}
			if err := request.Decode(); err != nil || request.Type != stun.BindingRequest {
				continue
			}
			address := remote.(*net.UDPAddr)
			response, err := stun.Build(stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess,
				&stun.XORMappedAddress{IP: address.IP, Port: address.Port})
			if err == nil {
				_, err = packets.WriteTo(response.Raw, remote)
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = packets.Close()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
}

func socketFixture(t *testing.T, ctx context.Context, address string) *Socket {
	t.Helper()
	s, err := ListenSocket(ctx, "udp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func gatherSocketAgent(t *testing.T, ctx context.Context, socket *Socket, urls []*stun.URI, loopback bool, accept func([]byte) bool) (*ice.Agent, []ice.Candidate) {
	t.Helper()
	agent, err := socket.newICE(urls, loopback, accept)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = agent.GracefulClose() })
	var mu sync.Mutex
	var candidates []ice.Candidate
	complete := make(chan struct{})
	if err := agent.OnCandidate(func(c ice.Candidate) {
		mu.Lock()
		defer mu.Unlock()
		if c == nil {
			close(complete)
		} else {
			candidates = append(candidates, c)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := agent.GatherCandidates(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-complete:
	case <-ctx.Done():
		t.Fatal("shared-socket gathering failed", ctx.Err())
	}
	mu.Lock()
	defer mu.Unlock()
	for _, c := range candidates {
		if _, err := netip.ParseAddr(c.Address()); err != nil || !c.NetworkType().IsUDP() || c.Type() != ice.CandidateTypeHost && c.Type() != ice.CandidateTypeServerReflexive {
			t.Fatal("gathered a non-IP UDP host/srflx candidate", c.Marshal(), err)
		}
	}
	return agent, candidates
}

func connectSocketAgents(t *testing.T, ctx context.Context, left *ice.Agent, leftCandidates []ice.Candidate, right *ice.Agent, rightCandidates []ice.Candidate) (*ice.Conn, *ice.Conn) {
	t.Helper()
	for _, c := range rightCandidates {
		if err := left.AddRemoteCandidate(c); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range leftCandidates {
		if err := right.AddRemoteCandidate(c); err != nil {
			t.Fatal(err)
		}
	}
	leftUfrag, leftPwd, err := left.GetLocalUserCredentials()
	if err != nil {
		t.Fatal(err)
	}
	rightUfrag, rightPwd, err := right.GetLocalUserCredentials()
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		conn *ice.Conn
		err  error
	}
	accepted := make(chan result, 1)
	go func() { conn, err := right.Accept(ctx, leftUfrag, leftPwd); accepted <- result{conn, err} }()
	leftConn, err := left.Dial(ctx, rightUfrag, rightPwd)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case other := <-accepted:
		if other.err != nil {
			t.Fatal(other.err)
		}
		return leftConn, other.conn
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		return nil, nil
	}
}

func TestPeerSocketSharesQUICSTUNAndICE(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			serverTLS, clientTLS := peerTLS(t)
			clientTLS.NextProtos = []string{muxsession.ALPN}
			listener, err := muxsession.ListenQUIC(address, serverTLS, muxsession.QUICConfig{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			serveSocketMappingFixture(t, ctx, listener)
			left, right := socketFixture(t, ctx, address), socketFixture(t, ctx, address)
			client, err := left.DialQUIC(ctx, listener.Addr(), clientTLS, nil)
			if err != nil {
				t.Fatal(err)
			}
			server, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.CloseWithError(0, ""); _ = server.Close() })
			roundTripQUIC := func() {
				t.Helper()
				stream, err := client.OpenStreamSync(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := stream.Write([]byte("quic")); err != nil {
					t.Fatal(err)
				}
				incoming, err := server.AcceptStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer incoming.Close()
				var data [4]byte
				if _, err := io.ReadFull(incoming, data[:]); err != nil || string(data[:]) != "quic" {
					t.Fatal("STUN/ICE interfered with QUIC", err)
				}
				stream.CancelRead(0)
				_ = stream.Close()
			}
			roundTripQUIC()
			url, err := stun.ParseURI("stun:" + listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			leftAgent, leftCandidates := gatherSocketAgent(t, ctx, left, []*stun.URI{url}, true, nil)
			rightAgent, rightCandidates := gatherSocketAgent(t, ctx, right, []*stun.URI{url}, true, nil)
			for i, candidates := range [][]ice.Candidate{leftCandidates, rightCandidates} {
				socket := []*Socket{left, right}[i]
				found := false
				for _, c := range candidates {
					if c.Port() != socket.LocalAddr().(*net.UDPAddr).Port {
						t.Fatal("ICE opened another socket", c.Marshal())
					}
					found = found || c.Type() == ice.CandidateTypeServerReflexive
				}
				if !found {
					t.Fatal("STUN did not discover the shared socket mapping")
				}
			}
			leftConn, rightConn := connectSocketAgents(t, ctx, leftAgent, leftCandidates, rightAgent, rightCandidates)
			if leftConn.LocalAddr().(*net.UDPAddr).Port != client.LocalAddr().(*net.UDPAddr).Port {
				t.Fatal("direct ICE and relay QUIC use different UDP sockets")
			}
			carrier, other := ICECarrier{Conn: leftConn}, ICECarrier{Conn: rightConn}
			for _, invalid := range [][]byte{nil, {0x40}, {0x80}} {
				if err := carrier.Send(ctx, invalid); !errors.Is(err, ErrConfiguration) {
					t.Fatal("carrier admitted a packet outside the non-QUIC discriminator", err)
				}
			}
			if err := carrier.Send(ctx, make([]byte, iceSocketPacketBytes+1)); !errors.Is(err, io.ErrShortBuffer) {
				t.Fatal("carrier admitted an oversized packet", err)
			}
			for _, frame := range [][]byte{{1}, {2, 3, 4}, bytes.Repeat([]byte{1}, iceSocketPacketBytes)} {
				if err := carrier.Send(ctx, frame); err != nil {
					t.Fatal(err)
				}
				got, err := other.Receive(ctx)
				if err != nil || !bytes.Equal(got, frame) {
					t.Fatal("ICE did not preserve direct packet bytes", err)
				}
			}
			roundTripQUIC()
			if err := leftAgent.GracefulClose(); err != nil {
				t.Fatal(err)
			}
			if err := rightAgent.GracefulClose(); err != nil {
				t.Fatal(err)
			}
			roundTripQUIC()
		})
	}
}

func TestSocketICESimultaneousSiblingsShareTheSameRemote(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	left, right := socketFixture(t, ctx, "127.0.0.1:0"), socketFixture(t, ctx, "127.0.0.1:0")
	var carriers [2][2]ICECarrier
	for i := range carriers {
		tag := byte(i + 1)
		filter := func(b []byte) bool { return len(b) != 0 && b[0] == tag }
		a, ac := gatherSocketAgent(t, ctx, left, nil, true, filter)
		b, bc := gatherSocketAgent(t, ctx, right, nil, true, filter)
		leftConn, rightConn := connectSocketAgents(t, ctx, a, ac, b, bc)
		carriers[i] = [2]ICECarrier{{Conn: leftConn}, {Conn: rightConn}}
	}
	for i, pair := range carriers {
		for direction := range pair {
			frame := []byte{byte(i + 1), byte(direction), 42}
			if err := pair[direction].Send(ctx, frame); err != nil {
				t.Fatal(err)
			}
			got, err := pair[1-direction].Receive(ctx)
			if err != nil || !bytes.Equal(got, frame) {
				t.Fatal("sibling stole the direct packet", err)
			}
		}
	}
	// cancellation belongs to one agent, never the shared socket or sibling.
	readCtx, readCancel := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() { _, err := carriers[0][0].Receive(readCtx); result <- err }()
	readCancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("carrier cancellation left a read blocked")
	}
	frame := []byte{2, 9, 8, 7}
	if err := carriers[1][0].Send(ctx, frame); err != nil {
		t.Fatal("cancellation closed a sibling's path", err)
	}
	if got, err := carriers[1][1].Receive(ctx); err != nil || !bytes.Equal(got, frame) {
		t.Fatal("sibling failed after carrier cancellation", err)
	}
}

func TestSocketICEAgentCloseJoinsSTUNGatherWithoutClosingSibling(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	socket := socketFixture(t, ctx, "127.0.0.1:0")
	blackhole, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	url, err := stun.ParseURI("stun:" + blackhole.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	agent, err := socket.NewICE([]*stun.URI{url}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer agent.GracefulClose()
	if err := agent.OnCandidate(func(ice.Candidate) {}); err != nil {
		t.Fatal(err)
	}
	if err := agent.GatherCandidates(); err != nil {
		t.Fatal(err)
	}
	_ = blackhole.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := blackhole.ReadFrom(make([]byte, 2048)); err != nil {
		t.Fatal("gathering did not send a STUN request", err)
	}
	start := time.Now()
	if err := agent.GracefulClose(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatal("canceled gathering waited for the STUN timeout", elapsed)
	}
	socket.mux.mu.Lock()
	pending := socket.mux.discoveries
	socket.mux.mu.Unlock()
	if pending != 0 {
		t.Fatal("agent close did not join gathering", pending)
	}
	_, candidates := gatherSocketAgent(t, ctx, socket, nil, true, nil)
	if len(candidates) == 0 {
		t.Fatal("agent close prevented a sibling from gathering")
	}
}

type socketTestPacket struct {
	net.PacketConn
	addr   net.Addr
	closed atomic.Int32
	drop   atomic.Bool
}

func (c *socketTestPacket) LocalAddr() net.Addr {
	if c.addr != nil {
		return c.addr
	}
	return c.PacketConn.LocalAddr()
}

func (c *socketTestPacket) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.drop.Load() {
		return len(b), nil
	}
	return c.PacketConn.WriteTo(b, addr)
}

func (c *socketTestPacket) Close() error {
	c.closed.Add(1)
	return c.PacketConn.Close()
}

func TestSocketICEConsentLossReportsFailureBeforeQUICIdle(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wrapped := &socketTestPacket{PacketConn: packet}
	left, err := ListenSocketPacket(ctx, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	right := socketFixture(t, ctx, "127.0.0.1:0")
	a, ac := gatherSocketAgent(t, ctx, left, nil, true, nil)
	b, bc := gatherSocketAgent(t, ctx, right, nil, true, nil)
	states := make(chan ice.ConnectionState, 16)
	if err := b.OnConnectionStateChange(func(state ice.ConnectionState) { states <- state }); err != nil {
		t.Fatal(err)
	}
	connectSocketAgents(t, ctx, a, ac, b, bc)
	wrapped.drop.Store(true)
	start := time.Now()
	disconnected := false
	for {
		select {
		case state := <-states:
			switch state {
			case ice.ConnectionStateDisconnected:
				disconnected = true
			case ice.ConnectionStateFailed:
				if !disconnected || time.Since(start) > 9*time.Second {
					t.Fatal("consent loss did not report bounded disconnect then failure", time.Since(start))
				}
				return
			}
		case <-ctx.Done():
			t.Fatal("consent loss outlived the direct recovery budget", ctx.Err())
		}
	}
}

func TestSocketICEGatheringHonorsLoopbackAndRejectsTURN(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	socket := socketFixture(t, ctx, "127.0.0.1:0")
	_, candidates := gatherSocketAgent(t, ctx, socket, nil, false, nil)
	if len(candidates) != 0 {
		t.Fatal("custom mux ignored the loopback preference")
	}
	for _, raw := range []string{"turn:127.0.0.1:3478", "stuns:127.0.0.1:5349", "stun:relay.invalid:3478"} {
		url, err := stun.ParseURI(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := socket.NewICE([]*stun.URI{url}, true); !errors.Is(err, ErrConfiguration) {
			t.Fatal("accepted non-UDP STUN discovery", raw, err)
		}
	}
	if _, err := socket.NewICE([]*stun.URI{nil}, true); !errors.Is(err, ErrConfiguration) {
		t.Fatal("accepted nil discovery server", err)
	}
	url, err := stun.ParseURI("stun:127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	agent, err := socket.NewICE([]*stun.URI{url, url, url, url}, true)
	if err != nil {
		t.Fatal("four resolved relay addresses were rejected", err)
	}
	_ = agent.GracefulClose()
	if _, err := socket.NewICE([]*stun.URI{url, url, url, url, url}, true); !errors.Is(err, ErrConfiguration) {
		t.Fatal("unbounded discovery URL inputs", err)
	}
}

func TestSocketOwnsBorrowedPacketOnSuccessAndError(t *testing.T) {
	for _, mode := range []string{"success", "canceled", "invalid address"} {
		t.Run(mode, func(t *testing.T) {
			packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			wrapped := &socketTestPacket{PacketConn: packet}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			if mode == "invalid address" {
				wrapped.addr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
			}
			socket, err := ListenSocketPacket(ctx, wrapped)
			if mode == "success" {
				if err != nil {
					t.Fatal(err)
				}
				if err := socket.Close(); err != nil {
					t.Fatal(err)
				}
				if err := socket.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || socket != nil {
				t.Fatal("invalid socket construction succeeded", socket, err)
			}
			if wrapped.closed.Load() != 1 {
				t.Fatal("socket did not close its owned packet exactly once", wrapped.closed.Load())
			}
		})
	}
}
