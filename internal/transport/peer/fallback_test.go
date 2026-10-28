package peer

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// reply gates leave real, key-bound probes running without supplying fresh
// success. data restoration is independent of that evidence.
type fallbackCarrier struct {
	Carrier
	data        atomic.Bool
	replies     atomic.Bool
	replyDrops  atomic.Uint64
	key         [32]byte
	role, index uint8
	ledger      *fallbackLedger
	closeOnce   sync.Once
	closeErr    error
}

func (c *fallbackCarrier) Send(ctx context.Context, frame []byte) error {
	packet, valid := authenticatePacket(frame, c.key, 1-c.role, int(c.index))
	if !valid {
		return tunnelv1.ErrPeerPacket
	}
	if packet.Kind == tunnelv1.PeerProbeReply && !c.replies.Load() {
		c.replyDrops.Add(1)
		return nil
	}
	if packet.Kind == tunnelv1.PeerData && !c.data.Load() {
		return nil
	}
	if err := c.Carrier.Send(ctx, frame); err != nil {
		return err
	}
	if packet.Kind == tunnelv1.PeerData {
		packet.Payload = bytes.Clone(packet.Payload)
		c.ledger.mu.Lock()
		if len(c.ledger.frames) < 512 {
			c.ledger.frames = append(c.ledger.frames, packet)
		} else {
			c.ledger.overflow = true
		}
		c.ledger.mu.Unlock()
	}
	return nil
}

func (c *fallbackCarrier) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.Carrier.Close() })
	return c.closeErr
}

type fallbackLedger struct {
	mu       sync.Mutex
	frames   []tunnelv1.PeerPacket
	overflow bool
}

func (l *fallbackLedger) copies(t *testing.T, packet []byte) [pathCount]int {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.overflow {
		t.Fatal("fallback fixture exceeded its bounded packet ledger")
	}
	type delivered struct {
		path     uint8
		sequence uint64
	}
	parts := make(map[delivered][]byte)
	masks := make(map[delivered]uint8)
	var counts [pathCount]int
	for _, frame := range l.frames {
		if frame.Sender != 0 || int(frame.Total) != len(packet) {
			continue
		}
		id := delivered{frame.Path, frame.Sequence}
		if parts[id] == nil {
			parts[id] = make([]byte, frame.Total)
		}
		copy(parts[id][int(frame.Fragment)*tunnelv1.PeerFragmentBytes:], frame.Payload)
		masks[id] |= 1 << frame.Fragment
	}
	needed := uint8(1)
	if len(packet) > tunnelv1.PeerFragmentBytes {
		needed = 3
	}
	for id, data := range parts {
		if masks[id] == needed && bytes.Equal(data, packet) {
			counts[id.path]++
		}
	}
	return counts
}

// this ordinary PacketConn wrapper gates the first real inner QUIC write. it
// adds no production hook and never changes endpoint selection or probe health.
type fallbackPacketConn struct {
	net.PacketConn
	ctx  context.Context
	mu   sync.Mutex
	next *fallbackWrite
}

type fallbackWrite struct {
	arrived chan []byte
	release chan struct{}
	done    chan fallbackWriteResult
	once    sync.Once
}

type fallbackWriteResult struct {
	path             int
	directDropBefore uint64
	directDropAfter  uint64
	err              error
}

func (c *fallbackPacketConn) arm(t *testing.T) *fallbackWrite {
	t.Helper()
	gate := &fallbackWrite{arrived: make(chan []byte, 1), release: make(chan struct{}), done: make(chan fallbackWriteResult, 1)}
	c.mu.Lock()
	if c.next != nil {
		c.mu.Unlock()
		t.Fatal("fallback packet gate already armed")
	}
	c.next = gate
	c.mu.Unlock()
	t.Cleanup(gate.open)
	return gate
}

func (g *fallbackWrite) open() { g.once.Do(func() { close(g.release) }) }

func (c *fallbackPacketConn) WriteTo(packet []byte, remote net.Addr) (int, error) {
	c.mu.Lock()
	gate := c.next
	c.next = nil
	c.mu.Unlock()
	if gate == nil {
		return c.PacketConn.WriteTo(packet, remote)
	}
	gate.arrived <- bytes.Clone(packet)
	select {
	case <-c.ctx.Done():
		return 0, context.Cause(c.ctx)
	case <-gate.release:
	}
	endpoint := c.PacketConn.(*Endpoint)
	before := endpoint.Stats(Direct).DroppedFrames
	n, err := endpoint.WriteTo(packet, remote)
	gate.done <- fallbackWriteResult{endpoint.ActivePath(), before, endpoint.Stats(Direct).DroppedFrames, err}
	return n, err
}

type fallbackConsumer struct {
	ctx         context.Context
	endpoints   [2]*Endpoint
	carriers    [2][pathCount]*fallbackCarrier
	slots       [2]*CarrierSlot
	connections [2]*quic.Conn
	packetConn  *fallbackPacketConn
	ledger      *fallbackLedger
	stream      *quic.Stream
	requests    atomic.Uint64
	counter     uint64
}

func newFallbackConsumer(t *testing.T, tcp [2]bool) *fallbackConsumer {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	t.Cleanup(cancel)
	f := &fallbackConsumer{ctx: ctx, ledger: &fallbackLedger{}}
	serverTLS, clientTLS := peerTLS(t)
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	var paths [2][pathCount]Carrier
	for index := range pathCount {
		var left, right Carrier
		if index == Direct {
			left, right = directPair(t)
		} else {
			left, right = relayPair(t, ctx, tcp[index], serverTLS, clientTLS)
		}
		for side, carrier := range []Carrier{left, right} {
			gate := &fallbackCarrier{Carrier: carrier, key: key, role: uint8(side), index: uint8(index), ledger: f.ledger}
			gate.data.Store(true)
			gate.replies.Store(index != Direct)
			f.carriers[side][index] = gate
			paths[side][index] = gate
			if index == Direct {
				f.slots[side] = NewCarrierSlot()
				paths[side][index] = f.slots[side]
				if err := f.slots[side].Install(gate); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	for side := range 2 {
		endpoint, err := New(ctx, Config{Key: key, Role: uint8(side), Paths: paths[side], ProbeInterval: 20 * time.Millisecond, PathTimeout: 120 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		f.endpoints[side] = endpoint
		t.Cleanup(func() { _ = endpoint.Close() })
	}
	f.packetConn = &fallbackPacketConn{PacketConn: f.endpoints[0], ctx: ctx}
	clientTransport := &quic.Transport{Conn: f.packetConn}
	serverTransport := &quic.Transport{Conn: f.endpoints[1]}
	t.Cleanup(func() { _ = clientTransport.Close(); _ = serverTransport.Close() })
	config := &quic.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true, MaxIdleTimeout: 5 * time.Second}
	listener, err := serverTransport.Listen(serverTLS, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	f.connections[0], err = clientTransport.Dial(ctx, f.endpoints[0].RemoteAddr(), clientTLS, config)
	if err != nil {
		t.Fatal(err)
	}
	f.connections[1], err = listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, conn := range f.connections {
			_ = conn.CloseWithError(0, "")
		}
	})
	f.stream, err = f.connections[0].OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.stream.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	incoming, err := f.connections[1].AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var first [1]byte
	if _, err := io.ReadFull(incoming, first[:]); err != nil {
		t.Fatal(err)
	}
	// the target is opened once. its counter is scoped to this real TCP socket;
	// an application replay or another target cannot satisfy the transcript.
	target, targetSide := tcpPair(t)
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			if _, err := io.ReadFull(target, first[:]); err != nil {
				return
			}
			count := f.requests.Add(1)
			if _, err := target.Write(binary.BigEndian.AppendUint64(nil, count)); err != nil {
				return
			}
		}
	})
	workers.Go(func() {
		for {
			var request [1]byte
			if _, err := io.ReadFull(incoming, request[:]); err != nil {
				return
			}
			if _, err := targetSide.Write(request[:]); err != nil {
				return
			}
			var reply [8]byte
			if _, err := io.ReadFull(targetSide, reply[:]); err != nil {
				return
			}
			if _, err := incoming.Write(reply[:]); err != nil {
				return
			}
		}
	})
	t.Cleanup(func() {
		incoming.CancelRead(0)
		incoming.CancelWrite(0)
		_ = target.Close()
		_ = targetSide.Close()
		workers.Wait()
	})
	return f
}

func (f *fallbackConsumer) exchange(t *testing.T, expectedPath int, gated bool) {
	t.Helper()
	// gating and all assertions spend this same absolute budget, not a new
	// three-second allowance after waiting for a packet or probe.
	deadline := time.Now().Add(3 * time.Second)
	ctx, cancel := context.WithDeadline(f.ctx, deadline)
	defer cancel()
	var gate *fallbackWrite
	if gated {
		gate = f.packetConn.arm(t)
	}
	if err := f.stream.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if _, err := f.stream.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if gate != nil {
		var packet []byte
		select {
		case packet = <-gate.arrived:
		case <-ctx.Done():
			t.Fatal("first restored QUIC packet did not reach its gate", ctx.Err())
		}
		f.assertUnhealthy(t)
		gate.open()
		select {
		case result := <-gate.done:
			if result.err != nil || result.path != expectedPath || result.directDropAfter != result.directDropBefore {
				t.Fatalf("first restored packet selected path=%d want=%d direct-drop delta=%d: %v", result.path, expectedPath, result.directDropAfter-result.directDropBefore, result.err)
			}
		case <-ctx.Done():
			t.Fatal("first restored packet did not leave its gate", ctx.Err())
		}
		for {
			copies := f.ledger.copies(t, packet)
			if copies[expectedPath] != 0 {
				want := [pathCount]int{}
				want[expectedPath] = 1
				if copies != want {
					t.Fatal("first encrypted packet was replayed or sent on another carrier", copies)
				}
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("first restored encrypted packet did not reach its one relay", ctx.Err())
			case <-time.After(time.Millisecond):
			}
		}
	}
	var reply [8]byte
	if _, err := io.ReadFull(f.stream, reply[:]); err != nil {
		t.Fatal("retained counter stream did not complete within its absolute budget", err)
	}
	f.counter++
	if binary.BigEndian.Uint64(reply[:]) != f.counter || f.requests.Load() != f.counter {
		t.Fatal("target state reset or application request replayed")
	}
	if gated {
		f.assertUnhealthy(t)
		t.Logf("first restored packet used relay=%d once; same counter=%d completed in %s with probe replies withheld", expectedPath, f.counter, 3*time.Second-time.Until(deadline))
	}
}

func (f *fallbackConsumer) assertUnhealthy(t *testing.T) {
	t.Helper()
	for side, endpoint := range f.endpoints {
		for index := range pathCount {
			if endpoint.PathHealthy(index) || f.carriers[side][index].replies.Load() {
				t.Fatalf("side=%d path=%d gained probe health or reply permission", side, index)
			}
		}
	}
}

func fallbackAwait(t *testing.T, ctx context.Context, ready func() bool) {
	t.Helper()
	for !ready() {
		select {
		case <-ctx.Done():
			t.Fatal("fallback fixture did not reach its gated state", ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
}

func TestPeerSpeculativeRelayFallbackRetainsCounterStream(t *testing.T) {
	for _, tcp := range [][2]bool{{false, false}, {true, true}, {false, true}, {true, false}} {
		t.Run(fmt.Sprintf("tls-yamux=%t/%t", tcp[0], tcp[1]), func(t *testing.T) {
			f := newFallbackConsumer(t, tcp)
			awaitPath(t, f.ctx, f.endpoints[0], f.endpoints[1], RelayA)
			f.exchange(t, RelayA, false)
			fallbackAwait(t, f.ctx, func() bool {
				return f.carriers[0][Direct].replyDrops.Load() != 0 && f.carriers[1][Direct].replyDrops.Load() != 0
			})
			for _, endpoint := range f.endpoints {
				if endpoint.PathHealthy(Direct) || endpoint.ActivePath() == Direct {
					t.Fatal("direct delivery bypassed fresh MAC probe replies")
				}
			}
			for side := range 2 {
				f.carriers[side][Direct].replies.Store(true)
			}
			awaitPath(t, f.ctx, f.endpoints[0], f.endpoints[1], Direct)
			f.exchange(t, Direct, false)
			for side := range 2 {
				for index := range pathCount {
					f.carriers[side][index].data.Store(false)
					f.carriers[side][index].replies.Store(false)
				}
			}
			fallbackAwait(t, f.ctx, func() bool {
				for _, endpoint := range f.endpoints {
					endpoint.mu.Lock()
					alive := false
					for _, path := range endpoint.paths {
						alive = alive || path.alive
					}
					endpoint.mu.Unlock()
					if alive {
						return false
					}
				}
				return true
			})
			for side := range 2 {
				for _, index := range []int{RelayA, RelayB} {
					f.carriers[side][index].data.Store(true)
				}
			}
			f.exchange(t, RelayA, true)
			// a closed first relay must not be revived as a speculative carrier.
			// the second remains bound; no session, stream, target or key changes.
			for side := range 2 {
				if err := f.carriers[side][RelayA].Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Fatal(err)
				}
			}
			fallbackAwait(t, f.ctx, func() bool {
				for _, endpoint := range f.endpoints {
					endpoint.mu.Lock()
					failed := endpoint.paths[RelayA].failed
					endpoint.mu.Unlock()
					if !failed {
						return false
					}
				}
				return true
			})
			f.exchange(t, RelayB, true)
		})
	}
}
