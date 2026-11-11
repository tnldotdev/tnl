package peer

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v4"
)

type socketBlockedPacket struct {
	net.PacketConn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *socketBlockedPacket) WriteTo(b []byte, addr net.Addr) (int, error) {
	select {
	case c.entered <- struct{}{}:
	default:
	}
	<-c.release
	return c.PacketConn.WriteTo(b, addr)
}

func (c *socketBlockedPacket) unblock() { c.once.Do(func() { close(c.release) }) }

func (c *socketBlockedPacket) Close() error {
	c.unblock()
	return c.PacketConn.Close()
}

func blockedSocketFixture(t *testing.T) (*Socket, *socketBlockedPacket) {
	t.Helper()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	blocked := &socketBlockedPacket{PacketConn: packet, entered: make(chan struct{}, 1), release: make(chan struct{})}
	socket, err := ListenSocketPacket(t.Context(), blocked)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := socket.Close(); err != nil {
			t.Error(err)
		}
	})
	return socket, blocked
}

func awaitSocketBlockedWrite(t *testing.T, blocked *socketBlockedPacket) {
	t.Helper()
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("physical write did not start")
	}
}

func TestSocketICEBlockedWriteRetiresLocallyAndPreservesSibling(t *testing.T) {
	for _, mode := range []string{"close", "deadline", "budget"} {
		t.Run(mode, func(t *testing.T) {
			socket, blocked := blockedSocketFixture(t)
			mux := &agentICEMux{socketICEMux: socket.mux}
			c, sibling := unitICEConn(t, mux, "blocked"), unitICEConn(t, mux, "sibling")
			remote, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer remote.Close()
			frame := []byte{1, 2, 3}
			result := make(chan error, 1)
			go func() { _, err := c.WriteTo(frame, remote.LocalAddr()); result <- err }()
			awaitSocketBlockedWrite(t, blocked)
			want := os.ErrDeadlineExceeded
			switch mode {
			case "close":
				want = net.ErrClosed
				_ = c.Close()
			case "deadline":
				_ = c.SetWriteDeadline(time.Now())
			}
			select {
			case err := <-result:
				if !errors.Is(err, want) {
					t.Fatal("blocked write did not retire locally", err)
				}
			case <-time.After(time.Second):
				t.Fatal("logical retirement waited for the physical write")
			}
			// the caller may reuse its buffer immediately after cancellation. the
			// socket still owns any physical write until it completes or is closed.
			frame[1] = 9
			blocked.unblock()
			if got := readICEPacket(t, remote); !bytes.Equal(got, []byte{1, 2, 3}) {
				t.Fatal("retired write retained the caller's buffer", got)
			}
			if _, err := sibling.WriteTo([]byte{4}, remote.LocalAddr()); err != nil {
				t.Fatal("logical retirement changed the sibling's socket or deadline", err)
			}
			if got := readICEPacket(t, remote); !bytes.Equal(got, []byte{4}) {
				t.Fatal("sibling could not use the physical socket", got)
			}
		})
	}
}

func TestSocketICEBlockedDiscoveryJoinsWithoutWaitingForPhysicalWrite(t *testing.T) {
	socket, blocked := blockedSocketFixture(t)
	url, err := stun.ParseURI("stun:127.0.0.1:9")
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
	awaitSocketBlockedWrite(t, blocked)
	closed := make(chan error, 1)
	go func() { closed <- agent.GracefulClose() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("closing the agent waited for a blocked physical discovery write")
	}
	socket.mux.mu.Lock()
	pending := socket.mux.discoveries
	socket.mux.mu.Unlock()
	if pending != 0 {
		t.Fatal("agent close retained a discovery caller", pending)
	}
	blocked.unblock()
	sibling := unitICEConn(t, &agentICEMux{socketICEMux: socket.mux}, "sibling")
	if _, err := sibling.WriteTo([]byte{1}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); err != nil {
		t.Fatal("canceling discovery closed or expired the sibling's socket", err)
	}
}

func TestSocketICEWriteQueueIsBoundedAndSocketCloseJoinsPhysicalWriter(t *testing.T) {
	socket, blocked := blockedSocketFixture(t)
	c := unitICEConn(t, &agentICEMux{socketICEMux: socket.mux}, "blocked")
	remote := netip.MustParseAddrPort("127.0.0.1:9")
	result := make(chan error, 1)
	go func() { _, err := c.WriteTo([]byte{1}, net.UDPAddrFromAddrPort(remote)); result <- err }()
	awaitSocketBlockedWrite(t, blocked)
	for range iceSocketQueue {
		socket.mux.writes <- iceSocketWrite{conn: c.icePacketConn, data: []byte{1}, remote: remote, expires: time.Now().Add(time.Second), result: make(chan iceSocketWriteResult, 1)}
	}
	if _, err := c.WriteTo([]byte{1}, net.UDPAddrFromAddrPort(remote)); !errors.Is(err, ErrConfiguration) {
		t.Fatal("blocked physical writer admitted an unbounded queue", err)
	}
	closed := make(chan error, 1)
	go func() { closed <- socket.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("socket close did not interrupt and join the physical writer")
	}
	select {
	case <-socket.mux.writeDone:
		if len(socket.mux.writes) != 0 {
			t.Fatal("closed socket retained queued writes")
		}
	default:
		t.Fatal("socket close returned before the writer joined")
	}
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("socket close left its logical writer blocked")
	}
}
