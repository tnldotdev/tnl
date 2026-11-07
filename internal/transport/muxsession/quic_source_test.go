package muxsession

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	quic "github.com/quic-go/quic-go"
)

// change only the server's observed source; packets retain real QUIC encryption
// and connection IDs. replies use the physical loopback socket on every host.
type relabeledQUICSocket struct {
	net.PacketConn
	moved     atomic.Bool
	portMoved atomic.Bool
	physical  sync.Map
}

func (p *relabeledQUICSocket) ReadFrom(buffer []byte) (int, net.Addr, error) {
	n, address, err := p.PacketConn.ReadFrom(buffer)
	if err != nil {
		return n, address, err
	}
	physical := address.(*net.UDPAddr)
	ip, port := physical.AddrPort().Addr(), uint16(physical.Port)
	if p.moved.Load() {
		ip = netip.MustParseAddr("127.0.0.2")
	}
	if p.portMoved.Load() {
		port = port%65535 + 1
	}
	advertised := netip.AddrPortFrom(ip, port)
	p.physical.Store(advertised, net.UDPAddrFromAddrPort(physical.AddrPort()))
	return n, net.UDPAddrFromAddrPort(advertised), nil
}

func (p *relabeledQUICSocket) WriteTo(buffer []byte, address net.Addr) (int, error) {
	physical, ok := p.physical.Load(address.(*net.UDPAddr).AddrPort())
	if !ok {
		return 0, errors.New("test: missing physical UDP destination")
	}
	return p.PacketConn.WriteTo(buffer, physical.(*net.UDPAddr))
}

func TestQUICSourcePinRejectsMigratedFramesBeforeDispatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relabeled := &relabeledQUICSocket{PacketConn: packet}
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, err := ListenQUICPacket(relabeled, serverTLS, QUICConfig{PinnedRemoteIPLimit: 4, Config: &quic.Config{EnableDatagrams: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	dial := func() (Session, Session) {
		t.Helper()
		client, err := (QUICConnector{TLSConfig: clientTLS, Config: QUICConfig{Config: &quic.Config{EnableDatagrams: true}}}).Connect(ctx, Endpoint{Address: listener.Addr().String(), ServerName: "relay.test"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		server, err := listener.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = server.Close() })
		if !server.(*quicSession).RemoteIPBound() {
			t.Fatal("source-pinned listener lost its transport capability")
		}
		return client, server
	}
	client, server := dial()
	if err := client.(DatagramSession).SendDatagram(ctx, []byte("original")); err != nil {
		t.Fatal(err)
	}
	if got, err := server.(DatagramSession).ReceiveDatagram(ctx); err != nil || string(got) != "original" {
		t.Fatal("original source could not deliver encrypted packets", err)
	}
	relabeled.portMoved.Store(true)
	if err := client.(DatagramSession).SendDatagram(ctx, []byte("same-IP NAT port")); err != nil {
		t.Fatal(err)
	}
	if got, err := server.(DatagramSession).ReceiveDatagram(ctx); err != nil || string(got) != "same-IP NAT port" {
		t.Fatal("source-IP isolation rejected same-IP port rebinding", err)
	}
	relabeled.portMoved.Store(false)
	relabeled.moved.Store(true)
	for range 4 {
		if err := client.(DatagramSession).SendDatagram(ctx, []byte("migrated")); err != nil {
			t.Fatal(err)
		}
	}
	quiet, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	defer stop()
	if got, err := server.(DatagramSession).ReceiveDatagram(quiet); !errors.Is(err, context.DeadlineExceeded) || got != nil {
		t.Fatal("a migrated datagram reached QUIC dispatch", err)
	}
	if source := server.(AcceptedPeer).RemoteAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(); source != netip.MustParseAddr("127.0.0.1") {
		t.Fatal("cross-IP packet changed established transport identity")
	}
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("not authorized on the new source")); err != nil {
		t.Fatal(err)
	}
	quietStream, stopStream := context.WithTimeout(ctx, 50*time.Millisecond)
	defer stopStream()
	if incoming, err := server.AcceptStream(quietStream); err == nil {
		_ = incoming.Close()
		t.Fatal("migrated stream bytes reached established QUIC")
	}
	nextClient, nextServer := dial()
	if source := nextServer.(AcceptedPeer).RemoteAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(); source != netip.MustParseAddr("127.0.0.2") {
		t.Fatal("fresh transport did not retain its new observed source")
	}
	assertRoundTrip(t, nextClient, nextServer, "fresh transport on the new source")
	if err := listener.StopAccepting(); err != nil {
		t.Fatal(err)
	}
	assertRoundTrip(t, nextClient, nextServer, "drain the existing source")
	if _, err := listener.Accept(ctx); !errors.Is(err, ErrClosed) {
		t.Fatal("draining listener accepted another connection", err)
	}
}

type scriptedQUICSocket struct {
	packets chan sourceQUICPacket
	done    chan struct{}
	read    atomic.Int32
}

func (s *scriptedQUICSocket) ReadFrom(buffer []byte) (int, net.Addr, error) {
	select {
	case packet := <-s.packets:
		s.read.Add(1)
		return copy(buffer, packet.data), packet.address, nil
	case <-s.done:
		return 0, nil, net.ErrClosed
	}
}
func (s *scriptedQUICSocket) WriteTo(buffer []byte, _ net.Addr) (int, error) { return len(buffer), nil }
func (s *scriptedQUICSocket) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	return nil
}
func (*scriptedQUICSocket) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:443"))
}
func (*scriptedQUICSocket) SetDeadline(time.Time) error      { return nil }
func (*scriptedQUICSocket) SetReadDeadline(time.Time) error  { return nil }
func (*scriptedQUICSocket) SetWriteDeadline(time.Time) error { return nil }

func TestQUICSourcePinBoundsUnauthenticatedSourcesAndJoinsShutdown(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	packet := &scriptedQUICSocket{packets: make(chan sourceQUICPacket, 100), done: make(chan struct{})}
	listener, err := ListenQUICPacket(packet, serverTLS, QUICConfig{PinnedRemoteIPLimit: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for index := range 100 {
		address := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)}), 443))
		data := bytes.Repeat([]byte{0}, 1200)
		data[0] = 0xc0
		packet.packets <- sourceQUICPacket{data: data, address: address}
	}
	packet.packets <- sourceQUICPacket{address: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:443"))}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for packet.read.Load() < 101 {
		select {
		case <-ctx.Done():
			t.Fatal("UDP input did not join", ctx.Err())
		case <-ticker.C:
		}
	}
	listener.sources.mu.Lock()
	count, pending, queued := len(listener.sources.sources), listener.sources.pending, listener.sources.queuedBytes
	listener.sources.mu.Unlock()
	if count != 3 || pending != 3 || queued > sourceQUICQueueBytes {
		t.Fatal("untrusted source allocation escaped its bounds", count, pending, queued)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	listener.sources.mu.Lock()
	queued = listener.sources.queuedBytes
	listener.sources.mu.Unlock()
	if queued != 0 {
		t.Fatal("closed source listener retained packet buffers", queued)
	}
}

func TestQUICSourcePinRejectsInvalidStartupBeforeTakingTraffic(t *testing.T) {
	for _, config := range []QUICConfig{
		{PinnedRemoteIPLimit: -1},
		{PinnedRemoteIPLimit: 3, Config: &quic.Config{Versions: []quic.Version{0}}},
	} {
		packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := packet.LocalAddr().String()
		serverTLS, _ := testTLSConfigs(t)
		listener, err := ListenQUICPacket(packet, serverTLS, config)
		if err == nil {
			_ = listener.Close()
			t.Fatal("source listener deferred invalid startup until incoming traffic")
		}
		reopened, err := net.ListenPacket("udp4", address)
		if err != nil {
			t.Fatal("failed source listener retained its reserved UDP port", err)
		}
		_ = reopened.Close()
	}
}

func TestQUICSourcePinReclaimsFailedHandshakeBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		serverTLS, _ := testTLSConfigs(t)
		packet := &scriptedQUICSocket{packets: make(chan sourceQUICPacket, 3), done: make(chan struct{})}
		listener, err := ListenQUICPacket(packet, serverTLS, QUICConfig{PinnedRemoteIPLimit: 3})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		for round := range 2 {
			for index := range 3 {
				data := make([]byte, 1200)
				data[0] = 0xc0
				packet.packets <- sourceQUICPacket{data: data, address: net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, byte(round), byte(index + 1)}), 443))}
			}
			synctest.Wait()
			listener.sources.mu.Lock()
			count, pending := len(listener.sources.sources), listener.sources.pending
			listener.sources.mu.Unlock()
			if count != 3 || pending != 3 {
				t.Fatal("failed handshakes did not consume their bounded source budget", count, pending)
			}
			time.Sleep(11 * time.Second)
			synctest.Wait()
			listener.sources.mu.Lock()
			count, pending, queued := len(listener.sources.sources), listener.sources.pending, listener.sources.queuedBytes
			listener.sources.mu.Unlock()
			if count != 0 || pending != 0 || queued != 0 {
				t.Fatal("failed handshakes retained source transports or packet buffers", count, pending, queued)
			}
		}
	})
}
