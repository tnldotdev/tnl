package peer

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type memoryCarrier struct {
	in, out chan []byte
	stop    chan struct{}
	once    sync.Once
}

func (c *memoryCarrier) Send(ctx context.Context, b []byte) error {
	select {
	case c.out <- bytes.Clone(b):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.stop:
		return net.ErrClosed
	}
}

func (c *memoryCarrier) Receive(ctx context.Context) ([]byte, error) {
	select {
	case b := <-c.in:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.stop:
		return nil, net.ErrClosed
	}
}

func (c *memoryCarrier) Close() error {
	c.once.Do(func() { close(c.stop) })
	return nil
}

func memoryPair() (*memoryCarrier, *memoryCarrier) {
	a, b := make(chan []byte, packetQueue), make(chan []byte, packetQueue)
	return &memoryCarrier{in: a, out: b, stop: make(chan struct{})}, &memoryCarrier{in: b, out: a, stop: make(chan struct{})}
}

func TestPeerRejectsWrongKeyDirectionPathAndReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	left, attacker := memoryPair()
	sibling, _ := memoryPair()
	key := [32]byte{1}
	e, err := New(ctx, Config{Kind: NativePeer, Key: key, Role: 1, Paths: [pathCount]Carrier{left, sibling}, ProbeInterval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	valid := tunnelv1.PeerPacket{Kind: tunnelv1.PeerData, Sequence: 42, Total: 3, Payload: []byte("abc")}
	encode := func(p tunnelv1.PeerPacket, key [32]byte, kind Kind) []byte {
		unsigned, err := p.AuthenticatedBytes()
		if err != nil {
			t.Fatal(err)
		}
		mac := hmac.New(sha256.New, key[:])
		_, _ = mac.Write([]byte(kind))
		_, _ = mac.Write([]byte{0})
		_, _ = mac.Write(unsigned)
		copy(p.MAC[:], mac.Sum(nil))
		b, err := p.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, mutate := range []func(*tunnelv1.PeerPacket, *[32]byte){
		func(_ *tunnelv1.PeerPacket, key *[32]byte) { key[0] = 2 },
		func(p *tunnelv1.PeerPacket, _ *[32]byte) { p.Sender = 1 },
		func(p *tunnelv1.PeerPacket, _ *[32]byte) { p.Path = 1 },
	} {
		p, k := valid, key
		mutate(&p, &k)
		if err := attacker.Send(ctx, encode(p, k, NativePeer)); err != nil {
			t.Fatal(err)
		}
	}
	if err := attacker.Send(ctx, encode(valid, key, PublicIngress)); err != nil {
		t.Fatal(err)
	}
	if err := attacker.Send(ctx, encode(valid, key, NativePeer)); err != nil {
		t.Fatal(err)
	}
	if err := e.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1200]byte
	if n, _, err := e.ReadFrom(b[:]); err != nil || string(b[:n]) != "abc" {
		t.Fatal("valid packet missing", err)
	}
	if err := attacker.Send(ctx, encode(valid, key, NativePeer)); err != nil {
		t.Fatal(err)
	}
	_ = e.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
	if _, _, err := e.ReadFrom(b[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("forgery or replay reached the QUIC packet reader", err)
	}
	if e.Stats(RelayA).ReceivedFrames != 2 {
		t.Fatal("invalid evidence affected authenticated counters", e.Stats(RelayA))
	}
}

func TestPeerFragmentReorderingDuplicationAndBounds(t *testing.T) {
	e := &Endpoint{input: make(chan []byte, packetQueue)}
	p := new(path)
	data := bytes.Repeat([]byte("p"), tunnelv1.MaxPeerPacketBytes)
	first := tunnelv1.PeerPacket{Kind: tunnelv1.PeerData, Sequence: 1, Total: uint16(len(data)), Payload: data[:tunnelv1.PeerFragmentBytes]}
	second := first
	second.Fragment, second.Payload = 1, data[tunnelv1.PeerFragmentBytes:]
	e.assemble(p, second)
	e.assemble(p, second)
	e.assemble(p, first)
	if got := <-e.input; !bytes.Equal(got, data) {
		t.Fatal("fragment reordering changed encrypted packet")
	}
	e.assemble(p, first)
	e.assemble(p, second)
	if len(e.input) != 0 {
		t.Fatal("duplicate fragments emitted another packet")
	}
	for seq := uint64(2); seq < 10000; seq++ {
		first.Sequence = seq
		e.assemble(p, first)
	}
	// expired fragments cannot reoccupy a ring slot or complete an old packet.
	second.Sequence = 1
	e.assemble(p, second)
	if len(e.input) != 0 || p.highest != 9999 {
		t.Fatal("old incomplete packet survived the bounded window")
	}
}

func TestPeerBlockedTCPCarrierCannotBlockAlternateRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	// a real unread TCP socket supplies backpressure below the packet queue.
	writer, reader := tcpPair(t)
	if err := writer.SetWriteBuffer(1024); err != nil {
		t.Fatal(err)
	}
	if err := reader.SetReadBuffer(1024); err != nil {
		t.Fatal(err)
	}
	blocked := &StreamCarrier{Conn: writer}
	a, b := memoryPair()
	c, d := memoryPair()
	key := [32]byte{1}
	makeEndpoint := func(role uint8, paths [pathCount]Carrier) *Endpoint {
		e, err := New(ctx, Config{Kind: NativePeer, Key: key, Role: role, Paths: paths, ProbeInterval: 10 * time.Millisecond, PathTimeout: 60 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = e.Close() })
		return e
	}
	left := makeEndpoint(0, [pathCount]Carrier{blocked, a})
	right := makeEndpoint(1, [pathCount]Carrier{c, b})
	defer d.Close()
	start := time.Now()
	// force enough packets through the unread socket to fill both its kernel
	// buffers and our fixed queue before the warm sibling is selected.
	for range 10000 {
		left.enqueue(RelayA, tunnelv1.PeerPacket{Kind: tunnelv1.PeerData, Sequence: left.seq.Add(1), Total: 1000, Payload: bytes.Repeat([]byte{7}, 1000)})
	}
	awaitPath(t, ctx, left, right, RelayB)
	stats := left.Stats(RelayA)
	if stats.DroppedFrames == 0 || stats.PeakQueuedFrames != packetQueue {
		t.Fatal("TCP backpressure did not reach the bounded queue", stats)
	}
	// drain arbitrary packets already in flight on the alternate, then verify
	// useful delivery without waiting for the blocked carrier to recover.
	if _, err := left.WriteTo([]byte("after backpressure"), left.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	_ = right.SetReadDeadline(time.Now().Add(time.Second))
	var packet [1200]byte
	for {
		n, _, err := right.ReadFrom(packet[:])
		if err != nil {
			t.Fatal(err)
		}
		if string(packet[:n]) == "after backpressure" {
			break
		}
	}
	t.Logf("TCP head-of-line escape=%s, queued bytes <= %d, drops=%d", time.Since(start), packetQueue*tunnelv1.MaxPeerFrameBytes, stats.DroppedFrames)
	cancel()
	if err := left.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := left.WriteTo([]byte{1}, left.RemoteAddr()); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed endpoint accepted packets", err)
	}
}
