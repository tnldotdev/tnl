package peer

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// pause only the body, after a real framed stream has committed its length.
// both cancellation and the original write deadline still interrupt this writer.
type pausedFrameConn struct {
	net.Conn
	armed           atomic.Bool
	header, release chan struct{}
	deadline        deadline
}

func (c *pausedFrameConn) SetWriteDeadline(at time.Time) error {
	c.deadline.set(at)
	return c.Conn.SetWriteDeadline(at)
}

func (c *pausedFrameConn) Write(b []byte) (int, error) {
	select {
	case <-c.header:
		for {
			timer, changed := c.deadline.wait()
			select {
			case <-c.release:
				timer.Stop()
				return c.Conn.Write(b)
			case <-changed:
				timer.Stop()
			case <-timer.C:
				return 0, os.ErrDeadlineExceeded
			}
		}
	default:
	}
	n, err := c.Conn.Write(b)
	if err == nil && len(b) == 2 && c.armed.CompareAndSwap(true, false) {
		close(c.header)
	}
	return n, err
}

func forwardPublisherPair(t *testing.T, ctx context.Context, tcp bool, connector *CarrierSlot) (*ForwardingRegistration, Carrier, PairBinding) {
	t.Helper()
	serverTLS, clientTLS := peerTLS(t)
	var left, right muxsession.Session
	if tcp {
		left, right = sharedTLSPair(t, ctx, serverTLS, clientTLS)
	} else {
		left, right = sharedQUICPair(t, ctx, serverTLS, clientTLS)
	}
	relay, err := NewSharedSession(ctx, left)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewSharedSession(ctx, right)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = relay.Close(); _ = publisher.Close() })
	a, b := sharedBinding(t, 1, RelayA)
	if rejected, err := relay.RegisterForwarding(a, true, nil); rejected != nil || !errors.Is(err, ErrConfiguration) {
		t.Fatal("forwarding registration accepted an unbound destination", err)
	}
	out, err := relay.RegisterForwarding(a, true, connector)
	if err != nil {
		t.Fatal(err)
	}
	in, err := publisher.Register(b, false)
	if err != nil {
		t.Fatal(err)
	}
	return out, in, a
}

func TestPeerForwardReplacementFinishesEnteredPublisherFrame(t *testing.T) {
	for _, boundary := range []string{"complete", "deadline", "authority"} {
		t.Run(boundary, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			source := NewCarrierSlot()
			output, receiver, binding := forwardPublisherPair(t, ctx, true, source)
			frame := func(seq uint64) []byte {
				return signedPacket(t, binding, tunnelv1.PeerPacket{Kind: tunnelv1.PeerData, Sequence: seq, Total: 1, Payload: []byte{byte(seq)}})
			}
			// introduce and retain the exact publisher registration and stream.
			if err := output.publisher.Send(ctx, frame(1)); err != nil {
				t.Fatal(err)
			}
			if _, err := receiver.Receive(ctx); err != nil {
				t.Fatal(err)
			}
			live := output.publisher.(*registeredStreamCarrier).live
			paused := &pausedFrameConn{Conn: live.Conn, header: make(chan struct{}), release: make(chan struct{}), deadline: deadline{changed: make(chan struct{})}}
			paused.armed.Store(true)
			live.Conn = paused
			release := sync.OnceFunc(func() { close(paused.release) })
			defer release()
			old, sender := memoryPair()
			defer sender.Close()
			if err := source.Install(old); err != nil {
				t.Fatal(err)
			}
			life, retire := context.WithCancel(ctx)
			done := make(chan error, 1)
			go func() { done <- output.ForwardToPublisher(life) }()
			defer func() { release(); retire(); _ = source.Close() }()
			if err := sender.Send(ctx, frame(42)); err != nil {
				t.Fatal(err)
			}
			awaitEndpointSignal(t, ctx, paused.header)
			next, successor := memoryPair()
			defer successor.Close()
			installed := make(chan error, 1)
			go func() { installed <- source.Install(next) }()
			awaitEndpointSignal(t, ctx, old.stop)
			if boundary == "authority" {
				retire()
			}
			if boundary != "complete" {
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("partial frame failure was suppressed")
					}
				case <-ctx.Done():
					t.Fatal("partial write did not honor its original bound")
				}
				if err := <-installed; err != nil {
					t.Fatal(err)
				}
				// the bridge owner retires this publisher leg on any failed write;
				// it never dispatches another frame into the incomplete record.
				_ = output.Close()
				if _, err := receiver.Receive(ctx); err == nil {
					t.Fatal("partial frame escaped")
				}
				return
			}
			select {
			case err := <-installed:
				t.Fatal("handoff interrupted an entered publisher frame", err)
			case <-time.After(30 * time.Millisecond):
			}
			release()
			if err := <-installed; err != nil {
				t.Fatal(err)
			}
			if got, err := receiver.Receive(ctx); err != nil || !bytes.Equal(got, frame(42)) {
				t.Fatal("committed frame did not finish", err)
			}
			if err := successor.Send(ctx, frame(42)); err != nil {
				t.Fatal(err)
			}
			if err := successor.Send(ctx, frame(43)); err != nil {
				t.Fatal(err)
			}
			if got, err := receiver.Receive(ctx); err != nil || !bytes.Equal(got, frame(43)) {
				t.Fatal("retained stream lost framing or replay history", err)
			}
			if output.publisher.(*registeredStreamCarrier).live != live {
				t.Fatal("reopened publisher stream")
			}
			retire()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("forwarder did not join")
			}
		})
	}
}

type heldForwardRead struct {
	forwardingCarrier
	held             atomic.Bool
	entered, release chan struct{}
}

func (c *heldForwardRead) receiveForward(ctx context.Context) (queuedFrame, error) {
	b, err := c.forwardingCarrier.receiveForward(ctx)
	if err == nil && c.held.CompareAndSwap(false, true) {
		close(c.entered)
		select {
		case <-c.release:
		case <-ctx.Done():
			return queuedFrame{}, ctx.Err()
		}
	}
	return b, err
}

type heldForwardClose struct {
	Carrier
	entered, release chan struct{}
}

func (c *heldForwardClose) Close() error { close(c.entered); <-c.release; return c.Carrier.Close() }

func TestPeerForwardFencesAllQueuedPublisherPackets(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	destination := NewCarrierSlot()
	defer destination.Close()
	old, remote := memoryPair()
	defer remote.Close()
	heldClose := &heldForwardClose{Carrier: old, entered: make(chan struct{}), release: make(chan struct{})}
	releaseClose := sync.OnceFunc(func() { close(heldClose.release) })
	defer releaseClose()
	if err := destination.Install(heldClose); err != nil {
		t.Fatal(err)
	}
	serverTLS, clientTLS := peerTLS(t)
	left, right := sharedQUICPair(t, ctx, serverTLS, clientTLS)
	owner, err := NewSharedSession(ctx, left)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	remoteOwner, err := NewSharedSession(ctx, right)
	if err != nil {
		t.Fatal(err)
	}
	defer remoteOwner.Close()
	a, b := sharedBinding(t, 1, RelayA)
	input, err := owner.RegisterForwarding(a, true, destination)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := remoteOwner.Register(b, false)
	if err != nil {
		t.Fatal(err)
	}
	frame := func(seq uint64) []byte {
		return signedPacket(t, b, tunnelv1.PeerPacket{Kind: tunnelv1.PeerData, Sender: 1, Sequence: seq, Total: 1, Payload: []byte{byte(seq)}})
	}
	sharedInput := input.publisher.(*SharedDatagramCarrier)
	waitQueued := func(count int) {
		t.Helper()
		for len(sharedInput.peer.in) != count {
			select {
			case <-ctx.Done():
				t.Fatal("input did not reach queue", ctx.Err())
			case <-time.After(time.Millisecond):
			}
		}
	}
	for _, seq := range []uint64{41, 42} {
		if err := sender.Send(ctx, frame(seq)); err != nil {
			t.Fatal(err)
		}
	}
	waitQueued(2)
	held := &heldForwardRead{forwardingCarrier: input.publisher, entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(held.release) })
	defer release()
	done := make(chan error, 1)
	input.publisher = held
	go func() { done <- input.ForwardToConnector(ctx) }()
	defer func() { release(); releaseClose(); cancel(); <-done }()
	awaitEndpointSignal(t, ctx, held.entered)
	next, successor := memoryPair()
	defer successor.Close()
	installed := make(chan error, 1)
	go func() { installed <- destination.Install(next) }()
	awaitEndpointSignal(t, ctx, heldClose.entered)
	// admitted during the removal/install gap must also remain fenced.
	if err := sender.Send(ctx, frame(43)); err != nil {
		t.Fatal(err)
	}
	waitQueued(2)
	releaseClose()
	if err := <-installed; err != nil {
		t.Fatal(err)
	}
	release()
	if err := sender.Send(ctx, frame(44)); err != nil {
		t.Fatal(err)
	}
	got, err := successor.Receive(ctx)
	if err != nil || !bytes.Equal(got, frame(44)) {
		t.Fatal("pre-install packet acquired successor generation", err)
	}
	quiet, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	defer stop()
	if _, err := successor.Receive(quiet); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("extra queued packet escaped", err)
	}
}

func TestPeerForwardReplacementCannotCompleteOldFragments(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(map[bool]string{false: "quic", true: "tls-tcp"}[tcp], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			source := NewCarrierSlot()
			defer source.Close()
			output, receiver, binding := forwardPublisherPair(t, ctx, tcp, source)
			old, sender := memoryPair()
			defer sender.Close()
			if err := source.Install(old); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- output.ForwardToPublisher(ctx) }()
			defer func() { cancel(); _ = source.Close(); <-done }()
			data := bytes.Repeat([]byte{7}, tunnelv1.MaxPeerPacketBytes)
			frame := func(seq uint64, part uint8) []byte {
				payload := data[:tunnelv1.PeerFragmentBytes]
				if part == 1 {
					payload = data[tunnelv1.PeerFragmentBytes:]
				}
				return signedPacket(t, binding, tunnelv1.PeerPacket{Kind: tunnelv1.PeerData, Sequence: seq, Fragment: part, Total: uint16(len(data)), Payload: payload})
			}
			if err := sender.Send(ctx, frame(42, 0)); err != nil {
				t.Fatal(err)
			}
			got, err := receiver.Receive(ctx)
			if err != nil {
				t.Fatal(err)
			}
			packet, err := tunnelv1.ParsePeerPacket(got)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := &Endpoint{input: make(chan queuedPacket, packetQueue)}
			path := &path{carrier: receiver}
			endpoint.assemble(path, packet, carrierRevision{})
			next, successor := memoryPair()
			defer successor.Close()
			if err := source.Install(next); err != nil {
				t.Fatal(err)
			}
			for _, f := range [][]byte{frame(42, 1), frame(42, 0), frame(43, 1), frame(43, 0)} {
				if err := successor.Send(ctx, f); err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				got, err := receiver.Receive(ctx)
				if err != nil {
					t.Fatal(err)
				}
				packet, err := tunnelv1.ParsePeerPacket(got)
				if err != nil || packet.Sequence != 43 {
					t.Fatal("old sequence crossed the handoff", packet.Sequence, err)
				}
				endpoint.assemble(path, packet, carrierRevision{})
			}
			if len(endpoint.input) != 1 {
				t.Fatal("mixed fragments or lost fresh packet")
			}
			if got := <-endpoint.input; !bytes.Equal(got.data, data) {
				t.Fatal("fresh fragments did not assemble")
			}
		})
	}
}

func TestPeerForwardRegistrationBindsBothDirections(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(map[bool]string{false: "quic", true: "tls-tcp"}[tcp], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			connector := NewCarrierSlot()
			defer connector.Close()
			registration, publisher, binding := forwardPublisherPair(t, ctx, tcp, connector)
			carrier, client := memoryPair()
			defer client.Close()
			if err := connector.Install(carrier); err != nil {
				t.Fatal(err)
			}
			life, retire := context.WithCancel(ctx)
			done := make(chan error, 2)
			go func() { done <- registration.ForwardToPublisher(life) }()
			go func() { done <- registration.ForwardToConnector(life) }()
			defer func() {
				retire()
				_ = connector.Close()
				_ = registration.Close()
				for range 2 {
					select {
					case err := <-done:
						if err == nil {
							t.Error("forwarder lost shutdown error")
						}
					case <-ctx.Done():
						t.Error("forwarding registration did not join", ctx.Err())
					}
				}
			}()
			frame := func(sender uint8, sequence uint64) []byte {
				return signedPacket(t, binding, tunnelv1.PeerPacket{Kind: tunnelv1.PeerData, Sender: sender, Sequence: sequence, Total: 1, Payload: []byte{byte(sequence)}})
			}
			if err := client.Send(ctx, frame(0, 41)); err != nil {
				t.Fatal(err)
			}
			if got, err := publisher.Receive(ctx); err != nil || !bytes.Equal(got, frame(0, 41)) {
				t.Fatal("bound publisher direction failed", err)
			}
			if err := publisher.Send(ctx, frame(1, 41)); err != nil {
				t.Fatal(err)
			}
			if got, err := client.Receive(ctx); err != nil || !bytes.Equal(got, frame(1, 41)) {
				t.Fatal("bound connector direction failed", err)
			}
			next, successor := memoryPair()
			defer successor.Close()
			if err := connector.Install(next); err != nil {
				t.Fatal(err)
			}
			for _, sequence := range []uint64{41, 42} {
				if err := successor.Send(ctx, frame(0, sequence)); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := publisher.Receive(ctx); err != nil || !bytes.Equal(got, frame(0, 42)) {
				t.Fatal("bound registration reset publisher replay history", err)
			}
			// a framed read already waiting at removal keeps its old stamp and
			// may drop the first reply. the next read must use the successor.
			for _, sequence := range []uint64{42, 43} {
				if err := publisher.Send(ctx, frame(1, sequence)); err != nil {
					t.Fatal(err)
				}
			}
			for {
				got, err := successor.Receive(ctx)
				if err != nil {
					t.Fatal("bound registration did not follow replacement", err)
				}
				if bytes.Equal(got, frame(1, 43)) {
					break
				}
				if !bytes.Equal(got, frame(1, 42)) {
					t.Fatal("bound registration delivered a stale reply")
				}
			}
		})
	}
}
