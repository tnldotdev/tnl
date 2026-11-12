package peer

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// run only the endpoint's send worker so probes and readers cannot acquire the
// admission locks or consume the packets whose dispatch this fixture observes.
func endpointSendWorker(t *testing.T, parent context.Context, carrier Carrier) (*Endpoint, *path, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	sibling := NewCarrierSlot()
	p := &path{carrier: carrier, queue: make(chan queuedFrame, packetQueue)}
	p.refreshRevisionLocked()
	e := &Endpoint{ctx: ctx, cancel: cancel, config: Config{Key: [32]byte{1}, ProbeInterval: time.Millisecond, PathTimeout: 20 * time.Millisecond},
		binding: BindingRevision{Generation: 1}, bindingActive: true, paths: [deliveryPathCount]*path{p, {carrier: sibling}}}
	done := make(chan struct{})
	go func() { defer close(done); e.sendLoop(RelayA, p) }()
	t.Cleanup(func() {
		cancel()
		_ = carrier.Close()
		_ = sibling.Close()
		cleanup, stop := context.WithTimeout(context.WithoutCancel(t.Context()), 3*time.Second)
		defer stop()
		awaitEndpointSignal(t, cleanup, done)
	})
	return e, p, done
}

func awaitEndpointSendState(t *testing.T, ready func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for !ready() {
		select {
		case <-ctx.Done():
			t.Fatal("endpoint send worker did not reach its expected state", ctx.Err())
		case <-ticker.C:
		}
	}
}

func blockEndpointPacketAdmission(t *testing.T, e *Endpoint, p *path, slot *CarrierSlot, revision carrierRevision, expire func()) {
	t.Helper()
	slot.mu.Lock()
	defer slot.mu.Unlock()
	p.queue <- queuedFrame{revision: revision, kind: tunnelv1.PeerData, data: []byte("expired packet")}
	// no other worker takes endpoint.mu. holding it proves sendLoop has created
	// its packet context and is blocked inside slot.enter, before any Send.
	awaitEndpointSendState(t, func() bool {
		if !e.mu.TryLock() {
			return true
		}
		e.mu.Unlock()
		return false
	})
	expire()
}

func crossEndpointPacketDeadline(t *testing.T, e *Endpoint) {
	t.Helper()
	// readiness was observed at the admission barrier before this timer starts.
	// cross the existing packet deadline without changing the owner context.
	timer := time.NewTimer(5 * e.config.PathTimeout)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-e.ctx.Done():
		t.Fatal("owner ended before its packet deadline", context.Cause(e.ctx))
	}
}

func TestPeerExpiredPacketAdmissionKeepsReplaceablePathAndSendWorker(t *testing.T) {
	slot := NewCarrierSlot()
	first, remote := memoryPair()
	defer remote.Close()
	if err := slot.Install(first); err != nil {
		t.Fatal(err)
	}
	e, p, done := endpointSendWorker(t, t.Context(), slot)
	blockEndpointPacketAdmission(t, e, p, slot, slot.Generation(), func() { crossEndpointPacketDeadline(t, e) })
	awaitEndpointSendState(t, func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		return p.failed || p.stats.DroppedFrames != 0
	})
	e.mu.Lock()
	failed, dropped := p.failed, p.stats.DroppedFrames
	e.mu.Unlock()
	if failed || dropped != 1 || e.ctx.Err() != nil {
		t.Fatalf("expired packet admission retired its replaceable path: failed=%t dropped=%d owner=%v", failed, dropped, e.ctx.Err())
	}
	if len(remote.in) != 0 {
		t.Fatal("expired packet entered the physical carrier")
	}
	select {
	case <-done:
		t.Fatal("expired packet ended the endpoint send worker")
	default:
	}
	next, successor := memoryPair()
	defer successor.Close()
	if err := slot.Install(next); err != nil {
		t.Fatal("expired packet permanently closed the replacement slot", err)
	}
	if _, err := e.WriteTo([]byte("later packet"), e.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	frame, err := successor.Receive(ctx)
	if err != nil {
		t.Fatal("the same endpoint send worker did not deliver to its successor", err)
	}
	packet, err := tunnelv1.VerifyPeerPacketFrame(frame, e.config.Key)
	if err != nil || packet.Kind != tunnelv1.PeerData || string(packet.Payload) != "later packet" {
		t.Fatal("successor received the expired packet or lost the later packet", err)
	}
	e.cancel()
	awaitEndpointSignal(t, ctx, done)
}

func TestPeerExpiredPacketAdmissionPreservesSlotErrorPrecedence(t *testing.T) {
	for _, boundary := range []string{"foreign revision", "closed slot"} {
		t.Run(boundary, func(t *testing.T) {
			slot := NewCarrierSlot()
			carrier, remote := memoryPair()
			defer remote.Close()
			if err := slot.Install(carrier); err != nil {
				t.Fatal(err)
			}
			revision, want := slot.Generation(), ErrConfiguration
			if boundary == "foreign revision" {
				foreign := NewCarrierSlot()
				defer foreign.Close()
				revision = foreign.Generation()
			} else {
				want = net.ErrClosed
				_ = slot.Close()
			}
			expired, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
			defer cancel()
			if entered, err := slot.enter(expired, revision); entered != nil || !errors.Is(err, want) {
				t.Fatal("expired packet masked the slot's error precedence", err)
			}
			e, p, done := endpointSendWorker(t, t.Context(), slot)
			blockEndpointPacketAdmission(t, e, p, slot, revision, func() { crossEndpointPacketDeadline(t, e) })
			ctx, stop := context.WithTimeout(t.Context(), 3*time.Second)
			defer stop()
			awaitEndpointSignal(t, ctx, done)
			e.mu.Lock()
			failed, dropped := p.failed, p.stats.DroppedFrames
			e.mu.Unlock()
			if !failed || dropped != 0 || len(remote.in) != 0 {
				t.Fatal("expired packet suppressed a terminal slot error", failed, dropped)
			}
		})
	}
}

func TestPeerPacketAdmissionOwnerStopRemainsTerminal(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancellation", true: "deadline"}[deadline], func(t *testing.T) {
			owner, stop := context.WithCancel(t.Context())
			if deadline {
				stop()
				owner, stop = context.WithTimeout(t.Context(), time.Second)
			}
			defer stop()
			slot := NewCarrierSlot()
			carrier, remote := memoryPair()
			defer remote.Close()
			if err := slot.Install(carrier); err != nil {
				t.Fatal(err)
			}
			e, p, done := endpointSendWorker(t, owner, slot)
			blockEndpointPacketAdmission(t, e, p, slot, slot.Generation(), func() {
				if !deadline {
					stop()
				}
				<-owner.Done()
				<-e.ctx.Done()
			})
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			awaitEndpointSignal(t, ctx, done)
			e.mu.Lock()
			failed, dropped := p.failed, p.stats.DroppedFrames
			e.mu.Unlock()
			if !failed || dropped != 0 || e.ctx.Err() == nil || len(remote.in) != 0 {
				t.Fatal("owner stop became a retryable packet drop", failed, dropped, e.ctx.Err())
			}
		})
	}
}

func TestPeerStaticCarrierSendTimeoutRemainsTerminal(t *testing.T) {
	carrier, remote := memoryPair()
	defer remote.Close()
	held := &heldEndpointCarrier{Carrier: carrier, entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	release := sync.OnceFunc(func() { close(held.release) })
	defer release()
	e, p, done := endpointSendWorker(t, t.Context(), held)
	p.queue <- queuedFrame{kind: tunnelv1.PeerData, data: []byte("entered packet")}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	awaitEndpointSignal(t, ctx, held.entered)
	awaitEndpointSignal(t, ctx, held.canceled)
	release()
	awaitEndpointSignal(t, ctx, done)
	e.mu.Lock()
	failed, dropped := p.failed, p.stats.DroppedFrames
	e.mu.Unlock()
	if !failed || dropped != 0 || e.ctx.Err() != nil {
		t.Fatal("an entered static-carrier timeout became a retryable packet drop", failed, dropped, e.ctx.Err())
	}
	awaitEndpointSignal(t, ctx, held.closed)
}
