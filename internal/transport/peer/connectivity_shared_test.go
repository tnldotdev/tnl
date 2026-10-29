package peer

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v4"
)

func startFixtureConnectivity(t *testing.T, f *connectivityFixture) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(f.ctx)
	results := make(chan error, 2)
	for side := range 2 {
		go func() {
			results <- ServeConnectivity(ctx, f.sockets[side], f.connections[side], f.packets[side], f.slots[side], f.binding, side == 0, ConnectivityOptions{IncludeLoopback: true})
		}()
	}
	var joined sync.Once
	finish := func() {
		joined.Do(func() {
			cancel()
			for range 2 {
				select {
				case err := <-results:
					if err != nil && !errors.Is(err, context.Canceled) {
						t.Error(err)
					}
				case <-time.After(2 * time.Second):
					t.Error("shared connectivity did not join")
				}
			}
		})
	}
	t.Cleanup(finish)
	return finish
}

func awaitHealthyDirect(t *testing.T, f *connectivityFixture, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, timeout)
	defer cancel()
	for !f.packets[0].PathHealthy(Direct) || !f.packets[1].PathHealthy(Direct) {
		select {
		case <-ctx.Done():
			t.Fatalf("shared-socket consumer did not establish healthy direct delivery: %v slots=%d/%d stats=%+v/%+v", ctx.Err(), f.slots[0].Generation(), f.slots[1].Generation(), f.packets[0].Stats(Direct), f.packets[1].Stats(Direct))
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestNativePeerConnectivitySharedSocketsKeepSiblingAcrossRestartAndClose(t *testing.T) {
	left, leftFault := faultSocket(t)
	right, rightFault := faultSocket(t)
	first := newConnectivityFixtureOnSockets(t, [2]*Socket{left, right}, 1, 30*time.Second)
	second := newConnectivityFixtureOnSockets(t, first.sockets, 2, 30*time.Second)
	firstExchange, secondExchange := connectivityCounter(t, first), connectivityCounter(t, second)
	relayExchange := sharedSocketQUICExchange(t, first.ctx, first.sockets[0])
	firstExchange()
	secondExchange()
	relayExchange()
	stopFirst := startFixtureConnectivity(t, first)
	awaitHealthyDirect(t, first, connectivitySetupTimeout+time.Second)
	// reorder consent replies relative to the first agent's packet writes.
	// an address-keyed mux sends the second agent's replies to the first agent;
	// transaction dispatch must not depend on whichever agent wrote last.
	leftFault.responseDelay.Store(int64(40 * time.Millisecond))
	rightFault.responseDelay.Store(int64(40 * time.Millisecond))
	startFixtureConnectivity(t, second)
	awaitHealthyDirect(t, second, connectivitySetupTimeout+time.Second)
	leftFault.responseDelay.Store(0)
	rightFault.responseDelay.Store(0)
	// with both relay carriers unavailable, only correctly dispatched ICE and
	// key-bound probes can keep both retained inner streams delivering bytes.
	first.relayDrop.Store(true)
	second.relayDrop.Store(true)
	for range 5 {
		firstExchange()
		secondExchange()
	}
	old := first.slots[0].Generation()
	first.relayDrop.Store(false)
	if err := first.slots[0].Install(nil); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	// explicit removal and the attempt's cleanup each advance the slot before
	// the next installation. wait for that installation, not just cleanup.
	for first.slots[0].Generation() <= old+2 {
		if time.Now().After(deadline) {
			t.Fatal("shared-socket agent did not restart")
		}
		secondExchange()
		time.Sleep(100 * time.Millisecond)
	}
	awaitHealthyDirect(t, first, 3*time.Second)
	first.relayDrop.Store(true)
	firstExchange()
	secondExchange()
	relayExchange()
	stopFirst()
	// cancellation closes the first agents, not the process socket or the
	// sibling's transaction and address associations. exercise consent past close.
	until := time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		secondExchange()
		time.Sleep(100 * time.Millisecond)
	}
	if !second.packets[0].PathHealthy(Direct) || !second.packets[1].PathHealthy(Direct) {
		t.Fatal("closing a sibling removed live ICE associations")
	}
	relayExchange()
}

func TestNativePeerConnectivitySharedSocketsKeepIPv4IPv6AndWildcard(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:0", ":0"} {
		t.Run(address, func(t *testing.T) {
			var sockets [2]*Socket
			for side := range 2 {
				var err error
				sockets[side], err = ListenSocket(t.Context(), "udp", address)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = sockets[side].Close() })
			}
			first := newConnectivityFixtureOnSockets(t, sockets, 1, 30*time.Second)
			second := newConnectivityFixtureOnSockets(t, sockets, 2, 30*time.Second)
			firstExchange, secondExchange := connectivityCounter(t, first), connectivityCounter(t, second)
			startFixtureConnectivity(t, first)
			startFixtureConnectivity(t, second)
			awaitHealthyDirect(t, first, connectivitySetupTimeout+time.Second)
			awaitHealthyDirect(t, second, connectivitySetupTimeout+time.Second)
			first.relayDrop.Store(true)
			second.relayDrop.Store(true)
			for range 3 {
				firstExchange()
				secondExchange()
			}
		})
	}
}

func TestNativePeerConnectivityCancellationJoinsSTUNGathering(t *testing.T) {
	f := newConnectivityFixture(t)
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	f.binding.RelayAddresses = [2]string{server.LocalAddr().String(), server.LocalAddr().String()}
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- ServeConnectivity(ctx, f.sockets[0], f.connections[0], f.packets[0], f.slots[0], f.binding, true, ConnectivityOptions{IncludeLoopback: true})
	}()
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	var request [2048]byte
	if _, _, err := server.ReadFrom(request[:]); err != nil {
		cancel()
		<-result
		t.Fatal("gathering never reached STUN", err)
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation waited for STUN gather timeout")
	}
}

// packetFaultConn drops native packets while leaving STUN consent checks alive.
// it wraps the actual process socket, below Pion and the retained inner QUIC.
type packetFaultConn struct {
	net.PacketConn
	drop          atomic.Bool
	responses     atomic.Uint64
	dropped       atomic.Uint64
	responseDelay atomic.Int64
}

func (c *packetFaultConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		if stun.IsMessage(b[:n]) {
			message := &stun.Message{Raw: b[:n]}
			if message.Decode() == nil && message.Type.Class == stun.ClassSuccessResponse {
				c.responses.Add(1)
				if delay := c.responseDelay.Load(); delay > 0 {
					time.Sleep(time.Duration(delay))
				}
			}
		} else if c.drop.Load() && n > 0 && b[0]&0xc0 == 0 {
			c.dropped.Add(1)
			continue
		}
		return n, addr, nil
	}
}

func faultSocket(t *testing.T) (*Socket, *packetFaultConn) {
	t.Helper()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fault := &packetFaultConn{PacketConn: packet}
	s := newSocket(t.Context(), fault)
	t.Cleanup(func() { _ = s.Close() })
	return s, fault
}

func TestNativePeerConnectivityRestartsWhenConsentLivesButPacketProbesFail(t *testing.T) {
	left, fault := faultSocket(t)
	right, _ := faultSocket(t)
	f := newConnectivityFixtureOnSockets(t, [2]*Socket{left, right}, 1, 30*time.Second)
	exchange := connectivityCounter(t, f)
	exchange()
	startFixtureConnectivity(t, f)
	awaitHealthyDirect(t, f, connectivitySetupTimeout+time.Second)
	exchange()
	old := f.slots[0].Generation()
	consentBefore := fault.responses.Load()
	f.relayDrop.Store(true)
	fault.drop.Store(true)
	start := time.Now()
	deadline := start.Add(7 * time.Second)
	for f.slots[0].Generation() == old {
		if time.Now().After(deadline) {
			t.Fatalf("packet-probe failure did not restart ICE before inner idle timeout: selected=%d healthy=%t consent responses=%d dropped=%d", f.packets[0].ActivePath(), f.packets[0].PathHealthy(Direct), fault.responses.Load()-consentBefore, fault.dropped.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if fault.responses.Load() <= consentBefore || fault.dropped.Load() == 0 {
		t.Fatal("fault did not retain STUN consent while dropping packet probes")
	}
	if f.connections[0].Context().Err() != nil || f.connections[1].Context().Err() != nil {
		t.Fatal("restart waited for inner connection timeout")
	}
	t.Logf("probe-driven restart=%s, live STUN responses=%d, dropped native packets=%d", time.Since(start), fault.responses.Load()-consentBefore, fault.dropped.Load())
	// restore signaling delivery, then require fresh direct evidence. the same
	// stream and real target socket must continue their monotonic counter.
	fault.drop.Store(false)
	f.relayDrop.Store(false)
	exchange()
	deadline = time.Now().Add(12 * time.Second)
	for f.slots[0].Generation() <= old+1 {
		if time.Now().After(deadline) {
			t.Fatal("probe-driven restart did not install a new carrier")
		}
		time.Sleep(20 * time.Millisecond)
	}
	awaitHealthyDirect(t, f, 3*time.Second)
	f.relayDrop.Store(true)
	exchange()
}
