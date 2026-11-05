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

func TestPeerCarrierReplacementCutsInputAndRetainsReplay(t *testing.T) {
	for _, dequeued := range []bool{false, true} {
		t.Run(map[bool]string{false: "queued", true: "dequeued"}[dequeued], func(t *testing.T) {
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
			if err := sender.Send(ctx, frame(42, "old")); err != nil {
				t.Fatal(err)
			}
			for len(e.input) == 0 {
				select {
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(time.Millisecond):
				}
			}
			var candidate queuedPacket
			if dequeued {
				candidate = <-e.input
			}
			next, successor := memoryPair()
			defer successor.Close()
			until := time.Now().Add(time.Second)
			_ = e.SetDeadline(until)
			sequence := e.seq.Load()
			if err := slot.Install(next); err != nil {
				t.Fatal(err)
			}
			if e.seq.Load() < sequence {
				t.Fatal("replacement reset output sequence")
			}
			if dequeued {
				buffer := bytes.Repeat([]byte{0x7f}, 32)
				if n, ok := candidate.copyTo(buffer); ok || n != 0 || !bytes.Equal(buffer, bytes.Repeat([]byte{0x7f}, 32)) {
					t.Fatal("stale copy committed")
				}
			}
			if err := successor.Send(ctx, frame(42, "old")); err != nil {
				t.Fatal(err)
			}
			if err := successor.Send(ctx, frame(43, "new")); err != nil {
				t.Fatal(err)
			}
			var buffer [32]byte
			if n, _, err := e.ReadFrom(buffer[:]); err != nil || string(buffer[:n]) != "new" {
				t.Fatal("stale packet or failed recovery", n, err)
			}
			e.read.mu.Lock()
			readUntil := e.read.at
			e.read.mu.Unlock()
			e.write.mu.Lock()
			writeUntil := e.write.at
			e.write.mu.Unlock()
			if readUntil != until || writeUntil != until {
				t.Fatal("replacement moved deadlines")
			}
			_ = e.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
			if _, _, err := e.ReadFrom(buffer[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("replayed input", err)
			}
		})
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
		t.Fatal("stale output retagged")
	}
	if err := slot.SendGeneration(t.Context(), []byte("old queue"), prior); err != nil || len(nextPeer.in) != 0 {
		t.Fatal("old output escaped", err)
	}
	data := bytes.Repeat([]byte{7}, tunnelv1.MaxPeerPacketBytes)
	first := tunnelv1.PeerPacket{Kind: tunnelv1.PeerData, Sequence: 43, Total: uint16(len(data)), Payload: data[:tunnelv1.PeerFragmentBytes]}
	second := first
	second.Fragment, second.Payload = 1, data[tunnelv1.PeerFragmentBytes:]
	e.assemble(p, first, prior)
	e.assemble(p, second, slot.Generation())
	if len(e.input) != 0 {
		t.Fatal("mixed registration fragments")
	}
	e.assemble(p, first, slot.Generation())
	if got := <-e.input; !bytes.Equal(got.data, data) {
		t.Fatal("successor could not assemble")
	}
	e.assemble(p, first, slot.Generation())
	e.assemble(p, second, slot.Generation())
	if len(e.input) != 0 {
		t.Fatal("replacement reset replay window")
	}
}

func TestPeerCarrierCutCancelsAndJoinsEnteredWork(t *testing.T) {
	for _, read := range []bool{false, true} {
		t.Run(map[bool]string{false: "send", true: "receive"}[read], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			slot := NewCarrierSlot()
			defer slot.Close()
			old, remote := memoryPair()
			defer remote.Close()
			held := &heldEndpointCarrier{Carrier: old, read: read, entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
			release := sync.OnceFunc(func() { close(held.release) })
			defer release()
			if err := slot.Install(held); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				if read {
					_, err := slot.Receive(ctx)
					done <- err
				} else {
					done <- slot.Send(ctx, []byte("entered"))
				}
			}()
			awaitEndpointSignal(t, ctx, held.entered)
			next, successor := memoryPair()
			defer successor.Close()
			installed := make(chan error, 1)
			go func() { installed <- slot.Install(next) }()
			awaitEndpointSignal(t, ctx, held.canceled)
			awaitEndpointSignal(t, ctx, held.closed)
			select {
			case err := <-installed:
				t.Fatal("did not join", err)
			default:
			}
			if err := slot.Send(ctx, []byte("before join")); err != nil || len(successor.in) != 0 {
				t.Fatal("successor became writable before predecessor joined", err)
			}
			closed := make(chan error, 1)
			go func() { closed <- slot.Close() }()
			for {
				slot.mu.Lock()
				fenced := slot.closed
				slot.mu.Unlock()
				if fenced {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(time.Millisecond):
				}
			}
			if err := slot.Send(ctx, []byte("forbidden")); !errors.Is(err, net.ErrClosed) {
				t.Fatal("close did not fence", err)
			}
			release()
			if err := <-installed; !errors.Is(err, net.ErrClosed) {
				t.Fatal("installation escaped concurrent close", err)
			}
			if err := <-closed; err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("unjoined carrier call")
			}
			late, peer := memoryPair()
			defer peer.Close()
			if err := slot.Install(late); !errors.Is(err, net.ErrClosed) {
				t.Fatal("install after shutdown", err)
			}
			select {
			case <-late.stop:
			default:
				t.Fatal("late carrier leaked")
			}
		})
	}
}
