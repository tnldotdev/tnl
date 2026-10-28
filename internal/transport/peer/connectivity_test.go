package peer

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type connectivityFixture struct {
	ctx         context.Context
	sockets     [2]*Socket
	packets     [2]*Endpoint
	slots       [2]*CarrierSlot
	connections [2]*quic.Conn
	binding     ConnectivityBinding
}

func newConnectivityFixture(t *testing.T) *connectivityFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)
	f := &connectivityFixture{ctx: ctx, binding: ConnectivityBinding{
		PairID: "npp_1234567890123456789012", DeliveryID: "AQEBAQEBAQEBAQEBAQEBAQ", Generation: 1,
		RelayAddresses: [2]string{"127.0.0.1:9", "127.0.0.1:9"},
	}}
	a, b := memoryPair()
	c, d := memoryPair()
	for side, relays := range [2][2]Carrier{{a, c}, {b, d}} {
		socket, err := ListenSocket(ctx, "udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		f.sockets[side] = socket
		t.Cleanup(func() { _ = socket.Close() })
		f.slots[side] = NewCarrierSlot()
		packets, err := New(ctx, Config{Kind: NativePeer, Key: [32]byte{1}, Role: uint8(side),
			Paths: [3]Carrier{relays[0], relays[1], f.slots[side]}, ProbeInterval: 20 * time.Millisecond, PathTimeout: 120 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		f.packets[side] = packets
		t.Cleanup(func() { _ = packets.Close() })
	}
	serverTLS, clientTLS := peerTLS(t)
	clientTransport, serverTransport := &quic.Transport{Conn: f.packets[0]}, &quic.Transport{Conn: f.packets[1]}
	t.Cleanup(func() { _ = clientTransport.Close(); _ = serverTransport.Close() })
	config := &quic.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true, MaxIncomingUniStreams: 1,
		MaxIdleTimeout: 5 * time.Second, KeepAlivePeriod: 100 * time.Millisecond}
	listener, err := serverTransport.Listen(serverTLS, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	f.connections[0], err = clientTransport.Dial(ctx, f.packets[0].RemoteAddr(), clientTLS, config)
	if err != nil {
		t.Fatal(err)
	}
	f.connections[1], err = listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, c := range f.connections {
			_ = c.CloseWithError(0, "")
		}
	})
	return f
}

func TestNativePeerConnectivityUpgradesAndFallsBackOnSameStream(t *testing.T) {
	f := newConnectivityFixture(t)
	relayExchange := sharedSocketQUICExchange(t, f.ctx, f.sockets[1])
	relayExchange()
	stream, err := f.connections[0].OpenStreamSync(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	in, err := f.connections[1].AcceptStream(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	var first [1]byte
	if _, err := io.ReadFull(in, first[:]); err != nil {
		t.Fatal(err)
	}
	// one actual target socket retains a counter through direct upgrade and loss.
	target, targetSide := tcpPair(t)
	var workers sync.WaitGroup
	workers.Go(func() {
		defer target.Close()
		var counter uint64
		for {
			if _, err := io.ReadFull(target, first[:]); err != nil {
				return
			}
			counter++
			if _, err := target.Write(binary.BigEndian.AppendUint64(nil, counter)); err != nil {
				return
			}
		}
	})
	workers.Go(func() {
		defer targetSide.Close()
		for {
			var request [1]byte
			if _, err := io.ReadFull(in, request[:]); err != nil {
				return
			}
			if _, err := targetSide.Write(request[:]); err != nil {
				return
			}
			var reply [8]byte
			if _, err := io.ReadFull(targetSide, reply[:]); err != nil {
				return
			}
			if _, err := in.Write(reply[:]); err != nil {
				return
			}
		}
	})
	t.Cleanup(func() {
		in.CancelRead(0)
		in.CancelWrite(0)
		_ = target.Close()
		_ = targetSide.Close()
		workers.Wait()
	})
	var counter uint64
	exchange := func() {
		t.Helper()
		if err := stream.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		var reply [8]byte
		if _, err := io.ReadFull(stream, reply[:]); err != nil {
			t.Fatal(err)
		}
		counter++
		if binary.BigEndian.Uint64(reply[:]) != counter {
			t.Fatal("target socket was replaced or bytes replayed")
		}
	}
	exchange()
	if f.packets[0].ActivePath() == Direct {
		t.Fatal("application did not start over a relay")
	}
	ctx, stop := context.WithCancel(f.ctx)
	results := make(chan error, 2)
	for side := range 2 {
		go func() {
			results <- ServeConnectivity(ctx, f.sockets[side], f.connections[side], f.packets[side], f.slots[side], f.binding, side == 0, ConnectivityOptions{IncludeLoopback: true})
		}()
	}
	t.Cleanup(func() {
		stop()
		for range 2 {
			select {
			case err := <-results:
				if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, ErrConnectivityConsent) {
					t.Error(err)
				}
			case <-time.After(time.Second):
				t.Error("connectivity shutdown did not join")
			}
		}
	})
	// signaling is still waiting on STUN, while the application remains usable.
	exchange()
	awaitPath(t, f.ctx, f.packets[0], f.packets[1], Direct)
	exchange()
	relayExchange()
	stop()
	deadline, finish := context.WithTimeout(f.ctx, 2*time.Second)
	defer finish()
	for f.packets[0].ActivePath() == Direct || f.packets[1].ActivePath() == Direct {
		select {
		case <-deadline.Done():
			t.Fatal("direct loss did not fall back")
		case <-time.After(10 * time.Millisecond):
		}
	}
	exchange()
	// canceling a peer must leave an actual relay QUIC connection on the same
	// physical socket usable, rather than merely allowing another agent object.
	relayExchange()
}

func sharedSocketQUICExchange(t *testing.T, ctx context.Context, socket *Socket) func() {
	t.Helper()
	serverTLS, clientTLS := peerTLS(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	client, err := socket.DialQUIC(ctx, listener.Addr(), clientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(0, ""); _ = server.CloseWithError(0, "") })
	if server.RemoteAddr().String() != socket.LocalAddr().String() {
		t.Fatal("relay QUIC did not share physical socket")
	}
	stream, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	incoming, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = io.Copy(incoming, incoming) }()
	t.Cleanup(func() { incoming.CancelRead(0); incoming.CancelWrite(0); <-done })
	var ready [1]byte
	if _, err := io.ReadFull(stream, ready[:]); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		if err := stream.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Write([]byte{42}); err != nil {
			t.Fatal("shared relay socket write", err)
		}
		var reply [1]byte
		if _, err := io.ReadFull(stream, reply[:]); err != nil || reply[0] != 42 {
			t.Fatal("shared relay socket read", err)
		}
	}
}

func TestNativePeerConnectivityRejectsCrossBindingAndBadCandidates(t *testing.T) {
	for name, test := range map[string]struct {
		change   func(*tunnelv1.NativePeerConnectivity)
		code     tunnelv1.ErrorCode
		trailing bool
	}{
		"pair":       {change: func(m *tunnelv1.NativePeerConnectivity) { m.PairID = "npp_2234567890123456789012" }, code: tunnelv1.Unauthenticated},
		"delivery":   {change: func(m *tunnelv1.NativePeerConnectivity) { m.DeliveryID = "AgICAgICAgICAgICAgICAg" }, code: tunnelv1.Unauthenticated},
		"generation": {change: func(m *tunnelv1.NativePeerConnectivity) { m.DeliveryGeneration++ }, code: tunnelv1.Unauthenticated},
		"hostname": {change: func(m *tunnelv1.NativePeerConnectivity) {
			m.Candidates = []string{"1 1 udp 2130706431 example.local 4443 typ host"}
		}, code: tunnelv1.InvalidMessage},
		"component": {change: func(m *tunnelv1.NativePeerConnectivity) {
			m.Candidates = []string{"1 2 udp 2130706431 127.0.0.1 4443 typ host"}
		}, code: tunnelv1.InvalidMessage},
		"malformed": {change: func(m *tunnelv1.NativePeerConnectivity) { m.Candidates = []string{"invalid"} }, code: tunnelv1.InvalidMessage},
		"trailing":  {change: func(*tunnelv1.NativePeerConnectivity) {}, code: tunnelv1.InvalidMessage, trailing: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newConnectivityFixture(t)
			ctx, cancel := context.WithCancel(f.ctx)
			result := make(chan error, 1)
			go func() {
				result <- ServeConnectivity(ctx, f.sockets[0], f.connections[0], f.packets[0], f.slots[0], f.binding, true, ConnectivityOptions{IncludeLoopback: true})
			}()
			joined := false
			t.Cleanup(func() {
				cancel()
				if !joined {
					<-result
				}
			})
			in, err := f.connections[1].AcceptUniStream(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			message, err := tunnelv1.ReadNativePeerConnectivity(in)
			if err != nil {
				t.Fatal(err)
			}
			test.change(&message)
			out, err := f.connections[1].OpenUniStreamSync(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := tunnelv1.WriteNativePeerConnectivity(out, message); err != nil {
				t.Fatal(err)
			}
			if test.trailing {
				if _, err := out.Write([]byte{0}); err != nil {
					t.Fatal(err)
				}
			}
			if err := out.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				joined = true
				var classified *ConnectivityError
				if !errors.As(err, &classified) || classified == nil || classified.Code != test.code {
					t.Fatal("wrong connectivity failure", err)
				}
			case <-time.After(time.Second):
				t.Fatal("invalid signal did not finish")
			}
			if f.slots[0].Generation() != 0 {
				t.Fatal("invalid signal installed packet authority")
			}
		})
	}
}

func TestNativePeerConnectivityCancellationInterruptsPartialSignal(t *testing.T) {
	f := newConnectivityFixture(t)
	ctx, cancel := context.WithCancel(f.ctx)
	result := make(chan error, 1)
	go func() {
		result <- ServeConnectivity(ctx, f.sockets[0], f.connections[0], f.packets[0], f.slots[0], f.binding, true, ConnectivityOptions{IncludeLoopback: true})
	}()
	t.Cleanup(cancel)
	in, err := f.connections[1].AcceptUniStream(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tunnelv1.ReadNativePeerConnectivity(in); err != nil {
		t.Fatal(err)
	}
	out, err := f.connections[1].OpenUniStreamSync(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	// announce a body but withhold it; only cancellation can release the reader.
	if _, err := out.Write(binary.BigEndian.AppendUint32(nil, 1024)); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("partial signaling frame blocked shutdown")
	}
	if f.packets[0].ActivePath() == Direct {
		t.Fatal("partial signal installed direct carrier")
	}
}

func TestNativePeerConnectivityCandidateValidation(t *testing.T) {
	for _, address := range []string{"0.0.0.0", "::", "224.0.0.1", "ff02::1", "host.local", "fe80::1%en0"} {
		candidate, err := ice.NewCandidateHost(&ice.CandidateHostConfig{Network: "udp", Address: address, Port: 1234, Component: 1})
		if err == nil && validConnectivityCandidate(candidate) {
			t.Fatalf("accepted candidate address %q", address)
		}
	}
	for _, address := range []string{"127.0.0.1", "192.0.2.1", "2001:db8::1"} {
		candidate, err := ice.NewCandidateHost(&ice.CandidateHostConfig{Network: "udp", Address: address, Port: 1234, Component: 1})
		if err != nil || !validConnectivityCandidate(candidate) {
			t.Fatalf("rejected IP candidate %q: %v", address, err)
		}
	}
	if validConnectivityCandidate(nil) {
		t.Fatal("accepted nil candidate")
	}
	var cause *ConnectivityError
	if errors.Unwrap(cause) != nil {
		t.Fatal("typed nil cause")
	}
	if !errors.Is(&ConnectivityError{Cause: net.ErrClosed}, net.ErrClosed) {
		t.Fatal("lost original cause")
	}
}
