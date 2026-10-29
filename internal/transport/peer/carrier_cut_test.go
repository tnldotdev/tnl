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

func TestPeerCarrierReplacementCutsEndpointInput(t *testing.T) {
	for _, dequeued := range []bool{false, true} {
		name := "queued"
		if dequeued {
			name = "dequeued-before-copy"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			slot := NewCarrierSlot()
			old, sender := memoryPair()
			defer sender.Close()
			if err := slot.Install(old); err != nil {
				t.Fatal(err)
			}
			sibling, unused := memoryPair()
			defer unused.Close()
			key := [32]byte{1}
			e, err := New(ctx, Config{Key: key, Role: 1, Paths: [pathCount]Carrier{slot, sibling}})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			binding := PairBinding{Key: key, Role: 0, Path: RelayA}
			frame := func(sequence uint64, data string) []byte {
				return signedPacket(t, binding, tunnelv1.PeerPacket{Kind: tunnelv1.PeerData, Sequence: sequence, Total: uint16(len(data)), Payload: []byte(data)})
			}
			if err := sender.Send(ctx, frame(42, "old packet")); err != nil {
				t.Fatal(err)
			}
			awaitCarrierCut(t, ctx, func() bool { return len(e.input) == 1 })
			var candidate queuedPacket
			if dequeued {
				// authentication, assembly and even dequeue are not input handoff.
				// retain the exact candidate used by ReadFrom's final copy.
				candidate = <-e.input
			}
			next, successor := memoryPair()
			defer successor.Close()
			until := time.Now().Add(time.Second)
			_ = e.SetDeadline(until)
			if err := slot.Install(next); err != nil {
				t.Fatal(err)
			}
			if dequeued {
				buffer := bytes.Repeat([]byte{0x7f}, 32)
				if n, ok := candidate.copyTo(buffer); ok || n != 0 || !bytes.Equal(buffer, bytes.Repeat([]byte{0x7f}, 32)) {
					t.Fatal("replacement allowed a stale caller-buffer commit")
				}
			}
			// replay remains spent across the cut, even when the old candidate
			// was never handed to QUIC. only a new packet can make progress.
			if err := successor.Send(ctx, frame(42, "old packet")); err != nil {
				t.Fatal(err)
			}
			if err := successor.Send(ctx, frame(43, "new packet")); err != nil {
				t.Fatal(err)
			}
			var buffer [32]byte
			if n, _, err := e.ReadFrom(buffer[:]); err != nil || string(buffer[:n]) != "new packet" {
				t.Fatal("cut terminated the logical reader or returned old input", n, string(buffer[:n]), err)
			}
			e.read.mu.Lock()
			readUntil := e.read.at
			e.read.mu.Unlock()
			e.write.mu.Lock()
			writeUntil := e.write.at
			e.write.mu.Unlock()
			if readUntil != until || writeUntil != until {
				t.Fatal("carrier replacement changed the original endpoint deadlines")
			}
			_ = e.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			if _, _, err := e.ReadFrom(buffer[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("spent packet reappeared after carrier replacement", err)
			}
		})
	}
}

func TestPeerCarrierReplacementPreservesCommittedInputPrefix(t *testing.T) {
	slot := NewCarrierSlot()
	defer slot.Close()
	old, sender := memoryPair()
	defer sender.Close()
	if err := slot.Install(old); err != nil {
		t.Fatal(err)
	}
	packet := queuedPacket{data: []byte("accepted prefix"), slot: slot, generation: slot.Generation()}
	var buffer [32]byte
	n, ok := packet.copyTo(buffer[:])
	if !ok {
		t.Fatal("current packet could not commit")
	}
	next, successor := memoryPair()
	defer successor.Close()
	if err := slot.Install(next); err != nil {
		t.Fatal(err)
	}
	// processing this already committed prefix is not a cut prerequisite.
	if string(buffer[:n]) != "accepted prefix" {
		t.Fatal("replacement changed committed caller input")
	}
}

func TestPeerCarrierReplacementDoesNotRetagOutputOrMixFragments(t *testing.T) {
	slot := NewCarrierSlot()
	defer slot.Close()
	old, oldPeer := memoryPair()
	defer oldPeer.Close()
	if err := slot.Install(old); err != nil {
		t.Fatal(err)
	}
	e := &Endpoint{config: Config{Key: [32]byte{1}}, input: make(chan queuedPacket, packetQueue)}
	p := &path{carrier: slot, queue: make(chan queuedFrame, packetQueue)}
	e.paths[RelayA] = p
	prior := slot.Generation()
	next, nextPeer := memoryPair()
	defer nextPeer.Close()
	if err := slot.Install(next); err != nil {
		t.Fatal(err)
	}
	e.enqueue(RelayA, tunnelv1.PeerPacket{Kind: tunnelv1.PeerData, Sequence: 42, Total: 1, Payload: []byte{1}}, prior)
	if len(p.queue) != 0 {
		t.Fatal("an output captured before the cut was retagged onto its successor")
	}
	data := bytes.Repeat([]byte{7}, tunnelv1.MaxPeerPacketBytes)
	first := tunnelv1.PeerPacket{Kind: tunnelv1.PeerData, Sequence: 43, Total: uint16(len(data)), Payload: data[:tunnelv1.PeerFragmentBytes]}
	second := first
	second.Fragment, second.Payload = 1, data[tunnelv1.PeerFragmentBytes:]
	e.assemble(p, first, prior)
	e.assemble(p, second, slot.Generation())
	if len(e.input) != 0 {
		t.Fatal("fragments from different physical registrations completed a packet")
	}
	e.assemble(p, first, slot.Generation())
	if got := <-e.input; !bytes.Equal(got.data, data) {
		t.Fatal("successor could not assemble its own complete packet")
	}
	e.assemble(p, first, slot.Generation())
	e.assemble(p, second, slot.Generation())
	if len(e.input) != 0 {
		t.Fatal("carrier replacement reset the endpoint's replay history")
	}
}

type heldCarrierCall struct {
	Carrier
	read     bool
	entered  chan struct{}
	canceled chan struct{}
	release  chan struct{}
	closed   chan struct{}
	once     sync.Once
	err      error
}

func (c *heldCarrierCall) call(ctx context.Context) error {
	close(c.entered)
	<-ctx.Done()
	close(c.canceled)
	<-c.release
	return ctx.Err()
}

func (c *heldCarrierCall) Send(ctx context.Context, b []byte) error {
	if !c.read {
		return c.call(ctx)
	}
	return c.Carrier.Send(ctx, b)
}

func (c *heldCarrierCall) Receive(ctx context.Context) ([]byte, error) {
	if c.read {
		return nil, c.call(ctx)
	}
	return c.Carrier.Receive(ctx)
}

func (c *heldCarrierCall) Close() error {
	c.once.Do(func() { _ = c.Carrier.Close(); close(c.closed) })
	return c.err
}

func TestPeerCarrierReplacementJoinsEnteredCalls(t *testing.T) {
	for _, read := range []bool{false, true} {
		name := "send"
		if read {
			name = "receive"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			slot := NewCarrierSlot()
			defer slot.Close()
			old, peer := memoryPair()
			defer peer.Close()
			held := &heldCarrierCall{Carrier: old, read: read, entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
			release := sync.OnceFunc(func() { close(held.release) })
			defer release()
			if err := slot.Install(held); err != nil {
				t.Fatal(err)
			}
			prior := slot.Generation()
			call := make(chan error, 1)
			go func() {
				if read {
					_, err := slot.Receive(ctx)
					call <- err
				} else {
					call <- slot.SendGeneration(ctx, []byte("entered"), prior)
				}
			}()
			awaitCarrierSignal(t, ctx, held.entered)
			next, successor := memoryPair()
			defer successor.Close()
			installed := make(chan error, 1)
			go func() { installed <- slot.Install(next) }()
			awaitCarrierSignal(t, ctx, held.canceled)
			awaitCarrierSignal(t, ctx, held.closed)
			select {
			case err := <-installed:
				t.Fatal("replacement returned before old carrier work completed", err)
			default:
			}
			// another pair has no dependency on this pair's cut or cleanup.
			sibling := NewCarrierSlot()
			defer sibling.Close()
			left, right := memoryPair()
			defer right.Close()
			if err := sibling.Install(left); err != nil {
				t.Fatal(err)
			}
			if err := right.Send(ctx, []byte("independent")); err != nil {
				t.Fatal(err)
			}
			if got, err := sibling.Receive(ctx); err != nil || string(got) != "independent" {
				t.Fatal("one pair's retiring call blocked its sibling", err)
			}
			if err := slot.SendGeneration(ctx, []byte("stale"), prior); err != nil || len(successor.in) != 0 {
				t.Fatal("old dispatch escaped while retirement was held", err)
			}
			if err := successor.Send(ctx, []byte("successor")); err != nil {
				t.Fatal(err)
			}
			release()
			if err := <-installed; err != nil {
				t.Fatal(err)
			}
			if err := <-call; err != nil {
				t.Fatal("carrier cut escaped as a permanent logical-path error", err)
			}
		})
	}
}

func TestPeerCarrierCloseFencesBeforeJoinedCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	slot := NewCarrierSlot()
	defer slot.Close()
	old, peer := memoryPair()
	defer peer.Close()
	closeErr := errors.New("first physical close")
	held := &heldCarrierCall{Carrier: old, entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{}), err: closeErr}
	release := sync.OnceFunc(func() { close(held.release) })
	defer release()
	if err := slot.Install(held); err != nil {
		t.Fatal(err)
	}
	call := make(chan error, 1)
	go func() { call <- slot.Send(ctx, []byte("entered")) }()
	awaitCarrierSignal(t, ctx, held.entered)
	closed := make(chan error, 2)
	go func() { closed <- slot.Close() }()
	awaitCarrierSignal(t, ctx, held.canceled)
	go func() { closed <- slot.Close() }()
	if err := slot.Send(ctx, []byte("forbidden")); !errors.Is(err, net.ErrClosed) {
		t.Fatal("close did not synchronously fence new dispatch", err)
	}
	if _, err := slot.Receive(ctx); !errors.Is(err, net.ErrClosed) {
		t.Fatal("close did not synchronously fence new reads", err)
	}
	select {
	case err := <-closed:
		t.Fatal("close returned before entered work completed", err)
	default:
	}
	release()
	for range 2 {
		if err := <-closed; !errors.Is(err, closeErr) {
			t.Fatal("concurrent closer lost the first physical close result", err)
		}
	}
	<-call
}

func awaitCarrierSignal(t *testing.T, ctx context.Context, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func awaitCarrierCut(t *testing.T, ctx context.Context, ready func() bool) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for !ready() {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
}
