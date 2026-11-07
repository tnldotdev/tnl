package relay

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
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type connectorSourcePeer struct {
	mu      sync.Mutex
	address net.Addr
}

func (p *connectorSourcePeer) RemoteAddr() net.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.address
}
func (*connectorSourcePeer) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:443"))
}
func (*connectorSourcePeer) TLSConnectionState() tls.ConnectionState { return tls.ConnectionState{} }
func (*connectorSourcePeer) RemoteIPBound() bool                     { return true }
func (p *connectorSourcePeer) move(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.address = net.UDPAddrFromAddrPort(netip.MustParseAddrPort(ip))
}

type connectorSourceTestCarrier struct {
	sends, receives atomic.Int32
	send, receive   func(context.Context) error
}

func (c *connectorSourceTestCarrier) Send(ctx context.Context, _ []byte) error {
	c.sends.Add(1)
	if c.send != nil {
		return c.send(ctx)
	}
	return nil
}
func (c *connectorSourceTestCarrier) Receive(ctx context.Context) ([]byte, error) {
	c.receives.Add(1)
	if c.receive != nil {
		if err := c.receive(ctx); err != nil {
			return nil, err
		}
	}
	return []byte("frame"), nil
}
func (*connectorSourceTestCarrier) Close() error { return nil }

func connectorSourceFixture(t *testing.T) (*connectorSourcePeer, *connectorSourceCarrier, *connectorSourceTestCarrier) {
	t.Helper()
	accepted := &connectorSourcePeer{}
	accepted.move("192.0.2.1:12345")
	source, err := newConnectorSocketSource(accepted)
	if err != nil {
		t.Fatal(err)
	}
	carrier := &connectorSourceTestCarrier{}
	return accepted, &connectorSourceCarrier{Carrier: carrier, source: source}, carrier
}

func TestConnectorSocketSourceUsesOnlyCanonicalAcceptedIP(t *testing.T) {
	for _, address := range []net.Addr{
		&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345},
		&net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 443},
	} {
		accepted := &connectorSourcePeer{address: address}
		source, err := newConnectorSocketSource(accepted)
		if err != nil || source.ip != netip.MustParseAddr("192.0.2.1") {
			t.Fatal("accepted IP was not canonical", err)
		}
		accepted.move("192.0.2.1:54321")
		if err := source.check(); err != nil {
			t.Fatal("source-port change changed IP authority", err)
		}
	}
	for _, address := range []net.Addr{nil, (*net.TCPAddr)(nil), (*net.UDPAddr)(nil), &net.UnixAddr{Name: "192.0.2.1:443"}, &net.UDPAddr{IP: net.IPv6zero, Port: 443}, &net.UDPAddr{IP: net.ParseIP("::ffff:0.0.0.0"), Port: 443}, &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 443, Zone: "en0"}} {
		if _, err := newConnectorSocketSource(&connectorSourcePeer{address: address}); !errors.Is(err, errConnectorSocketSource) {
			t.Fatal("noncanonical accepted source was allowed", address, err)
		}
	}
}

func TestConnectorSocketSourceRequiresPreDispatchIPBindingForUDP(t *testing.T) {
	accepted := &connectorSourcePeer{}
	accepted.move("192.0.2.1:443")
	// embedding only the address capability deliberately hides its IP fence.
	unbound := struct{ muxsession.AcceptedPeer }{accepted}
	if _, err := newConnectorSocketSource(unbound); !errors.Is(err, errConnectorSocketSource) {
		t.Fatal("UDP address snapshot was treated as a pre-dispatch IP fence", err)
	}
}

func TestConnectorSocketSourceFencesBothPacketDirectionsWithoutRenewal(t *testing.T) {
	for _, direction := range []string{"send", "receive"} {
		t.Run(direction, func(t *testing.T) {
			accepted, carrier, physical := connectorSourceFixture(t)
			accepted.move("192.0.2.2:12345")
			var err error
			if direction == "send" {
				err = carrier.Send(t.Context(), []byte("frame"))
			} else {
				var frame []byte
				frame, err = carrier.Receive(t.Context())
				if frame != nil {
					t.Fatal("migrated packet reached forwarding")
				}
			}
			if !errors.Is(err, errConnectorSocketSourceChanged) || physical.sends.Load() != 0 || physical.receives.Load() != 0 {
				t.Fatal("source migration entered a packet operation", err)
			}
			accepted.move("192.0.2.1:12345")
			if err := carrier.Send(t.Context(), []byte("frame")); !errors.Is(err, errConnectorSocketSourceChanged) {
				t.Fatal("old source returning revived its physical binding", err)
			}
		})
	}
}

func TestConnectorSocketSourceRejectsMigrationDuringEnteredReceive(t *testing.T) {
	for _, cause := range []error{nil, io.ErrUnexpectedEOF} {
		accepted, carrier, physical := connectorSourceFixture(t)
		physical.receive = func(context.Context) error {
			accepted.move("192.0.2.2:12345")
			return cause
		}
		frame, err := carrier.Receive(t.Context())
		if frame != nil || !errors.Is(err, errConnectorSocketSourceChanged) || cause != nil && !errors.Is(err, cause) {
			t.Fatal("read completion lost migration or its transport cause", err)
		}
	}
}

func TestConnectorSocketSourceJoinsEnteredSendWithinItsOriginalDeadline(t *testing.T) {
	accepted, carrier, physical := connectorSourceFixture(t)
	entered := make(chan struct{})
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	deadline, _ := ctx.Deadline()
	physical.send = func(call context.Context) error {
		if got, ok := call.Deadline(); !ok || got != deadline {
			t.Error("source fence changed entered write deadline")
		}
		close(entered)
		<-call.Done()
		return context.Cause(call)
	}
	done := make(chan error, 1)
	go func() { done <- carrier.Send(ctx, []byte("frame")) }()
	<-entered
	accepted.move("192.0.2.2:12345")
	select {
	case err := <-done:
		t.Fatal("migration interrupted entered framed write", err)
	default:
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, errConnectorSocketSourceChanged) {
			t.Fatal("entered send lost original deadline or stale source", err)
		}
	case <-time.After(time.Second):
		t.Fatal("entered framed write did not join")
	}
	if err := carrier.Send(t.Context(), []byte("next frame")); !errors.Is(err, errConnectorSocketSourceChanged) || physical.sends.Load() != 1 {
		t.Fatal("migrated stream was reused after an entered write", err)
	}
}

func connectorBindingFrame(t *testing.T, kind tunnelv1.PeerPacketKind) []byte {
	t.Helper()
	packet := tunnelv1.PeerPacket{Kind: kind, BindingGeneration: 2, Sender: 0, Path: 0, Sequence: 1, Total: 16, Payload: make([]byte, 16)}
	frame, err := packet.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestConnectorBindingPreparedAndUnspecifiedStateCarryOnlyProbes(t *testing.T) {
	for _, state := range []tunnelv1.ConnectorPeerLegBindingState{"", tunnelv1.ConnectorPeerLegBindingPrepared} {
		physical := &connectorSourceTestCarrier{}
		binding := newConnectorBindingCarrier(physical, nil, state)
		for _, kind := range []tunnelv1.PeerPacketKind{tunnelv1.PeerData, tunnelv1.PeerProbe, tunnelv1.PeerProbeReply} {
			before := physical.sends.Load()
			if err := binding.Send(t.Context(), connectorBindingFrame(t, kind)); err != nil {
				t.Fatal(err)
			}
			got := physical.sends.Load() - before
			if kind == tunnelv1.PeerData && got != 0 || kind != tunnelv1.PeerData && got != 1 {
				t.Fatal("pending data escaped or probes were blocked", state, kind, got)
			}
		}
		// endpoint frame MACs are deliberately zero here. only endpoints hold
		// SessionKey; the relay gate may inspect packet shape, not verify that MAC.
		binding.active.Store(true)
		before := physical.sends.Load()
		if err := binding.Send(t.Context(), connectorBindingFrame(t, tunnelv1.PeerData)); err != nil || physical.sends.Load() != before+1 {
			t.Fatal("explicit active confirmation did not allow data", err)
		}
	}
}

type connectorGateReadCarrier struct {
	*connectorSourceTestCarrier
	frames chan []byte
}

func (c *connectorGateReadCarrier) Receive(ctx context.Context) ([]byte, error) {
	select {
	case frame := <-c.frames:
		return frame, nil
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

func TestConnectorBindingPreparedInputDropsDataAndStillChecksEachSourceRead(t *testing.T) {
	accepted, sourceCarrier, _ := connectorSourceFixture(t)
	raw := &connectorGateReadCarrier{connectorSourceTestCarrier: &connectorSourceTestCarrier{}, frames: make(chan []byte, 2)}
	binding := newConnectorBindingCarrier(raw, sourceCarrier.source, tunnelv1.ConnectorPeerLegBindingPrepared)
	raw.frames <- connectorBindingFrame(t, tunnelv1.PeerData)
	probe := connectorBindingFrame(t, tunnelv1.PeerProbe)
	raw.frames <- probe
	got, err := binding.Receive(t.Context())
	if err != nil || string(got) != string(probe) || len(raw.frames) != 0 {
		t.Fatal("prepared data escaped or blocked probe reception", err)
	}
	accepted.move("192.0.2.2:12345")
	if _, err := binding.Receive(t.Context()); !errors.Is(err, errConnectorSocketSourceChanged) {
		t.Fatal("pending receive ignored source migration", err)
	}
	if err := binding.Send(t.Context(), connectorBindingFrame(t, tunnelv1.PeerData)); !errors.Is(err, errConnectorSocketSourceChanged) {
		t.Fatal("probe-only filtering skipped source authority", err)
	}
}
