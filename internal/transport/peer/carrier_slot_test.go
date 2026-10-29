package peer

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestPeerCarrierReplacementFencesOldQueuedPacketsAndReaders(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	slot := NewCarrierSlot()
	defer slot.Close()
	old, oldPeer := memoryPair()
	defer oldPeer.Close()
	if err := slot.Install(old); err != nil {
		t.Fatal(err)
	}
	prior := slot.Generation()
	type result struct {
		data []byte
		err  error
	}
	received := make(chan result, 1)
	go func() { b, err := slot.Receive(ctx); received <- result{b, err} }()
	next, nextPeer := memoryPair()
	defer nextPeer.Close()
	if err := slot.Install(next); err != nil {
		t.Fatal(err)
	}
	if err := slot.SendGeneration(ctx, []byte("stale queued data"), prior); err != nil {
		t.Fatal(err)
	}
	if len(nextPeer.in) != 0 {
		t.Fatal("old validated path queued data onto an unvalidated replacement")
	}
	if err := nextPeer.Send(ctx, []byte("new path")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if got.err != nil || string(got.data) != "new path" {
			t.Fatal("old carrier close terminated the logical path", got.err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := slot.Close(); err != nil {
		t.Fatal(err)
	}
	late, latePeer := memoryPair()
	defer latePeer.Close()
	if err := slot.Install(late); !errors.Is(err, net.ErrClosed) {
		t.Fatal("late setup survived shutdown", err)
	}
	select {
	case <-late.stop:
	default:
		t.Fatal("late carrier was not closed")
	}
}

func TestPeerCarrierReplacementRequiresFreshValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	a, b := memoryPair()
	c, d := memoryPair()
	defer b.Close()
	defer d.Close()
	slot := NewCarrierSlot()
	old, oldPeer := memoryPair()
	defer oldPeer.Close()
	if err := slot.Install(old); err != nil {
		t.Fatal(err)
	}
	e, err := New(ctx, Config{Role: 0, Key: [32]byte{1}, Paths: [pathCount]Carrier{a, c, slot}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.mu.Lock()
	e.paths[Direct].generation = slot.Generation()
	e.paths[Direct].alive = true
	e.active = Direct
	e.mu.Unlock()
	next, nextPeer := memoryPair()
	defer nextPeer.Close()
	if err := slot.Install(next); err != nil {
		t.Fatal(err)
	}
	if _, err := e.WriteTo([]byte("application packet"), e.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	validated := e.paths[Direct].alive
	e.mu.Unlock()
	if validated {
		t.Fatal("new direct carrier inherited the old path round trip")
	}
}
