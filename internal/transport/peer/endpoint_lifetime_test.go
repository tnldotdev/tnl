package peer

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPeerFragmentsStayWithTheirFixedCarrier(t *testing.T) {
	e := &Endpoint{input: make(chan []byte, packetQueue)}
	left, right := new(path), new(path)
	data := bytes.Repeat([]byte{7}, tunnelv1.MaxPeerPacketBytes)
	first := tunnelv1.PeerPacket{Kind: tunnelv1.PeerData, Sequence: 43, Total: uint16(len(data)), Payload: data[:tunnelv1.PeerFragmentBytes]}
	second := first
	second.Fragment, second.Payload = 1, data[tunnelv1.PeerFragmentBytes:]
	e.assemble(left, first)
	e.assemble(right, second)
	if len(e.input) != 0 {
		t.Fatal("fragments from different relay carriers completed a packet")
	}
	e.assemble(right, first)
	if got := <-e.input; !bytes.Equal(got, data) {
		t.Fatal("one carrier could not assemble its own packet")
	}
	e.assemble(right, first)
	e.assemble(right, second)
	if len(e.input) != 0 {
		t.Fatal("completed packet bypassed the replay window")
	}
}

func TestPeerQueuedInputHonorsDeadlineAndClose(t *testing.T) {
	for _, closing := range []bool{false, true} {
		t.Run(map[bool]string{false: "deadline", true: "close"}[closing], func(t *testing.T) {
			left, sender := memoryPair()
			defer sender.Close()
			right, unused := memoryPair()
			defer unused.Close()
			e, err := New(t.Context(), Config{Key: [32]byte{1}, Paths: [pathCount]Carrier{left, right}})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			e.input <- []byte("queued before the fence")
			want := os.ErrDeadlineExceeded
			if closing {
				want = net.ErrClosed
				if err := e.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				_ = e.SetDeadline(time.Now().Add(-time.Second))
			}
			buffer := bytes.Repeat([]byte{0x7f}, 32)
			if n, _, err := e.ReadFrom(buffer); n != 0 || !errors.Is(err, want) || !bytes.Equal(buffer, bytes.Repeat([]byte{0x7f}, 32)) {
				t.Fatal("queued packet committed after its input fence", n, err)
			}
			if _, err := e.WriteTo([]byte("forbidden"), e.RemoteAddr()); !errors.Is(err, want) {
				t.Fatal("endpoint accepted output after its fence", err)
			}
		})
	}
}

func TestPeerBothTerminalCarriersEndPacketReads(t *testing.T) {
	left, unusedLeft := memoryPair()
	defer unusedLeft.Close()
	right, unusedRight := memoryPair()
	defer unusedRight.Close()
	e, err := New(t.Context(), Config{Key: [32]byte{1}, Paths: [pathCount]Carrier{left, right}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	_ = left.Close()
	// one failed fixed carrier must leave its sibling available.
	e.fail(RelayA)
	if _, err := e.WriteTo([]byte("sibling"), e.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	_ = right.Close()
	_ = e.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := e.ReadFrom(make([]byte, 32)); !errors.Is(err, net.ErrClosed) {
		t.Fatal("terminal carriers waited for idle timeout", err)
	}
	if _, err := e.WriteTo([]byte("forbidden"), e.RemoteAddr()); !errors.Is(err, net.ErrClosed) {
		t.Fatal("terminal carriers accepted output", err)
	}
}

type heldEndpointCarrier struct {
	Carrier
	read     bool
	entered  chan struct{}
	canceled chan struct{}
	release  chan struct{}
	closed   chan struct{}
	once     sync.Once
	err      error
}

func (c *heldEndpointCarrier) call(ctx context.Context) error {
	close(c.entered)
	<-ctx.Done()
	close(c.canceled)
	<-c.release
	return ctx.Err()
}

func (c *heldEndpointCarrier) Send(ctx context.Context, b []byte) error {
	if !c.read {
		return c.call(ctx)
	}
	return c.Carrier.Send(ctx, b)
}

func (c *heldEndpointCarrier) Receive(ctx context.Context) ([]byte, error) {
	if c.read {
		return nil, c.call(ctx)
	}
	return c.Carrier.Receive(ctx)
}

func (c *heldEndpointCarrier) Close() error {
	c.once.Do(func() { _ = c.Carrier.Close(); close(c.closed) })
	return c.err
}

func TestPeerEndpointCloseFencesAndJoinsEnteredCarrierCalls(t *testing.T) {
	for _, read := range []bool{false, true} {
		t.Run(map[bool]string{false: "send", true: "receive"}[read], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			left, sender := memoryPair()
			defer sender.Close()
			right, unused := memoryPair()
			defer unused.Close()
			closeErr := errors.New("first physical close")
			held := &heldEndpointCarrier{Carrier: left, read: read, entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{}), err: closeErr}
			release := sync.OnceFunc(func() { close(held.release) })
			defer release()
			e, err := New(ctx, Config{Key: [32]byte{1}, Paths: [pathCount]Carrier{held, right}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { release(); _ = e.Close() }()
			awaitEndpointSignal(t, ctx, held.entered)
			closed := make(chan error, 2)
			go func() { closed <- e.Close() }()
			awaitEndpointSignal(t, ctx, held.canceled)
			awaitEndpointSignal(t, ctx, held.closed)
			go func() { closed <- e.Close() }()
			if _, err := e.WriteTo([]byte("forbidden"), e.RemoteAddr()); !errors.Is(err, net.ErrClosed) {
				t.Fatal("close did not fence new output", err)
			}
			if _, _, err := e.ReadFrom(make([]byte, 32)); !errors.Is(err, net.ErrClosed) {
				t.Fatal("close did not fence new input", err)
			}
			select {
			case err := <-closed:
				t.Fatal("close returned before entered carrier work completed", err)
			default:
			}
			// another pair is independent of this pair's held cleanup.
			a, b := memoryPair()
			c, d := memoryPair()
			first, err := New(ctx, Config{Key: [32]byte{2}, Paths: [pathCount]Carrier{a, c}})
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			second, err := New(ctx, Config{Key: [32]byte{2}, Role: 1, Paths: [pathCount]Carrier{b, d}})
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			if _, err := first.WriteTo([]byte("independent"), first.RemoteAddr()); err != nil {
				t.Fatal(err)
			}
			_ = second.SetReadDeadline(time.Now().Add(time.Second))
			var buffer [32]byte
			if n, _, err := second.ReadFrom(buffer[:]); err != nil || string(buffer[:n]) != "independent" {
				t.Fatal("one pair's cleanup blocked its sibling", err)
			}
			release()
			for range 2 {
				select {
				case err := <-closed:
					if !errors.Is(err, closeErr) {
						t.Fatal("concurrent closer lost the physical close result", err)
					}
				case <-ctx.Done():
					t.Fatal("endpoint did not join", ctx.Err())
				}
			}
		})
	}
}

func awaitEndpointSignal(t *testing.T, ctx context.Context, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
