package peer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v4"
	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const directPacketOverhead = tunnelv1.ConnectorPeerDirectHeaderBytes + tunnelv1.ConnectorPeerDirectTagBytes

type connectivityGate struct {
	net.PacketConn
	dropDirect atomic.Bool
	dropChecks atomic.Bool
	directSent atomic.Uint64
}

func (g *connectivityGate) WriteTo(packet []byte, addr net.Addr) (int, error) {
	if len(packet) > directPacketOverhead && packet[0] == tunnelv1.Version && !stun.IsMessage(packet) {
		g.directSent.Add(1)
		if g.dropDirect.Load() {
			return len(packet), nil
		}
	}
	if g.dropChecks.Load() && stun.IsMessage(packet) {
		message := &stun.Message{Raw: packet}
		if message.Decode() == nil && message.Contains(stun.AttrUsername) {
			return len(packet), nil
		}
	}
	return g.PacketConn.WriteTo(packet, addr)
}

type connectivityFixture struct {
	ctx         context.Context
	cancel      context.CancelFunc
	endpoints   [2]*Endpoint
	relays      [2][2]*CarrierSlot
	connections [2]*quic.Conn
	owners      [2]*Connectivity
	gates       [2]*connectivityGate
	checks      [2]atomic.Int32
	attempts    [2]chan ConnectivityAttempt
	fallbacks   [2]chan struct{}
	done        [2]chan error
	binding     ConnectivityBinding
}

func newConnectivityFixture(t *testing.T) *connectivityFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	f := &connectivityFixture{ctx: ctx, cancel: cancel}
	t.Cleanup(cancel)
	discovery, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	discoveryDone := make(chan struct{})
	go func() {
		defer close(discoveryDone)
		var buffer [2048]byte
		for {
			n, addr, err := discovery.ReadFrom(buffer[:])
			if err != nil {
				return
			}
			message := &stun.Message{Raw: buffer[:n]}
			if message.Decode() != nil || message.Type != stun.BindingRequest {
				continue
			}
			udp := addr.(*net.UDPAddr)
			response, err := stun.Build(stun.NewTransactionIDSetter(message.TransactionID), stun.BindingSuccess, &stun.XORMappedAddress{IP: udp.IP, Port: udp.Port}, stun.Fingerprint)
			if err == nil {
				_, _ = discovery.WriteTo(response.Raw, addr)
			}
		}
	}()
	t.Cleanup(func() { _ = discovery.Close(); <-discoveryDone })
	f.binding = ConnectivityBinding{Revision: BindingRevision{PairID: "cpp_1234567890123456789012", Generation: 1}, DeliveryID: "AQEBAQEBAQEBAQEBAQEBAQ", RelayAddresses: [2]string{discovery.LocalAddr().String(), discovery.LocalAddr().String()}}
	for slot := range 2 {
		a, b := memoryPair()
		for side, carrier := range []Carrier{a, b} {
			f.relays[side][slot] = NewCarrierSlot()
			if err := f.relays[side][slot].Install(carrier); err != nil {
				t.Fatal(err)
			}
		}
	}
	var sockets [2]*Socket
	for side := range 2 {
		f.endpoints[side], err = New(ctx, Config{Role: uint8(side), Key: [32]byte{3}, Binding: f.binding.Revision,
			Paths: [2]Carrier{f.relays[side][0], f.relays[side][1]}, Direct: NewCarrierSlot(), ProbeInterval: 10 * time.Millisecond, PathTimeout: 60 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.endpoints[side].Close() })
		packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		f.gates[side] = &connectivityGate{PacketConn: packet}
		sockets[side], err = ListenSocketPacket(ctx, f.gates[side])
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sockets[side].Close() })
	}
	awaitPath(t, ctx, f.endpoints[0], f.endpoints[1], RelayA)
	serverTLS, clientTLS := peerTLS(t)
	serverTransport := &quic.Transport{Conn: f.endpoints[1]}
	t.Cleanup(func() { _ = serverTransport.Close() })
	config := &quic.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true, MaxIncomingUniStreams: 2, MaxIdleTimeout: 30 * time.Second}
	listener, err := serverTransport.Listen(serverTLS, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	clientTransport := &quic.Transport{Conn: f.endpoints[0]}
	t.Cleanup(func() { _ = clientTransport.Close() })
	f.connections[0], err = clientTransport.Dial(ctx, f.endpoints[0].RemoteAddr(), clientTLS, config)
	if err != nil {
		t.Fatal(err)
	}
	f.connections[1], err = listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for side := range 2 {
		f.attempts[side] = make(chan ConnectivityAttempt, 32)
		f.fallbacks[side] = make(chan struct{}, 32)
		f.owners[side] = NewConnectivity(sockets[side], f.connections[side], f.endpoints[side], side == 0, ConnectivityOptions{IncludeLoopback: true, Observe: func(state ConnectivityState) {
			if state == ConnectivityChecking {
				f.checks[side].Add(1)
			}
		}, ObserveAttempt: func(attempt ConnectivityAttempt) { f.attempts[side] <- attempt }, ObserveFallback: func() { f.fallbacks[side] <- struct{}{} }}, nil)
	}
	return f
}

func (f *connectivityFixture) start(t *testing.T) {
	t.Helper()
	for side := range 2 {
		f.done[side] = make(chan error, 1)
		f.owners[side].SetBinding(f.binding)
		go func() { f.done[side] <- f.owners[side].Serve(f.ctx) }()
	}
	t.Cleanup(func() {
		f.cancel()
		for _, done := range f.done {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
	})
}

func (f *connectivityFixture) exchange(t *testing.T) func() {
	t.Helper()
	out, err := f.connections[0].OpenStreamSync(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		in, err := f.connections[1].AcceptStream(f.ctx)
		if err == nil {
			_, _ = io.Copy(in, in)
		}
	}()
	t.Cleanup(func() {
		out.CancelRead(0)
		out.CancelWrite(0)
		f.cancel()
		_ = f.connections[1].CloseWithError(0, "")
		<-echoDone
	})
	var counter byte
	return func() {
		t.Helper()
		counter++
		if err := out.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := out.Write([]byte{counter}); err != nil {
			t.Fatal(err)
		}
		var reply [1]byte
		if _, err := io.ReadFull(out, reply[:]); err != nil || reply[0] != counter {
			t.Fatal("retained application stream lost its exchange", err)
		}
	}
}

func TestConnectorConnectivityDirectFallbackAndRebindingRetainInnerStream(t *testing.T) {
	f := newConnectivityFixture(t)
	exchange := f.exchange(t)
	exchange() // application bytes flow before either ICE agent exists.
	f.start(t)
	awaitPath(t, f.ctx, f.endpoints[0], f.endpoints[1], Direct)
	for side := range 2 {
		select {
		case attempt := <-f.attempts[side]:
			if attempt.Outcome != "succeeded" || attempt.Duration <= 0 {
				t.Fatalf("direct attempt: %+v", attempt)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("direct attempt was not observed")
		}
	}
	exchange()
	if f.gates[0].directSent.Load() == 0 || f.gates[1].directSent.Load() == 0 {
		t.Fatal("direct selection carried no UDP frames")
	}
	for _, gate := range f.gates {
		gate.dropDirect.Store(true) // consent still passes; packet probes must fence it.
	}
	awaitPath(t, f.ctx, f.endpoints[0], f.endpoints[1], RelayA)
	for side := range 2 {
		select {
		case <-f.fallbacks[side]:
		case <-time.After(3 * time.Second):
			t.Fatal("direct fallback was not observed")
		}
	}
	exchange()
	for _, gate := range f.gates {
		gate.dropDirect.Store(false)
	}
	awaitPath(t, f.ctx, f.endpoints[0], f.endpoints[1], Direct)
	exchange()
	// each endpoint keeps its one QUIC connection while authority stages and
	// proves the replacement relays. direct cannot supply either relay proof.
	f.binding.Revision = testBinding(2)
	for _, owner := range f.owners {
		owner.Suspend()
	}
	for _, endpoint := range f.endpoints {
		if err := endpoint.StageBinding(f.binding.Revision); err != nil {
			t.Fatal(err)
		}
	}
	for slot := range 2 {
		a, b := memoryPair()
		for side, carrier := range []Carrier{a, b} {
			if err := f.endpoints[side].InstallBindingCarrier(f.binding.Revision, slot, carrier); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, endpoint := range f.endpoints {
		awaitBindingProofs(t, f.ctx, endpoint, f.binding.Revision)
		if err := endpoint.ActivateBinding(f.binding.Revision); err != nil {
			t.Fatal(err)
		}
	}
	exchange()
	for _, owner := range f.owners {
		owner.SetBinding(f.binding)
	}
	awaitPath(t, f.ctx, f.endpoints[0], f.endpoints[1], Direct)
	exchange()
}

func TestConnectorConnectivityFailedFirstAttemptRetriesOverRelays(t *testing.T) {
	f := newConnectivityFixture(t)
	for _, gate := range f.gates {
		gate.dropChecks.Store(true)
	}
	exchange := f.exchange(t)
	f.start(t)
	deadline := time.NewTimer(12 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for f.checks[0].Load() < 2 {
		select {
		case <-f.ctx.Done():
			t.Fatal(f.ctx.Err())
		case <-deadline.C:
			// a setup may spend its full ten-second budget before gathering
			// the second offer. useful relay traffic remains available meanwhile.
			exchange()
		case <-ticker.C:
			exchange()
		}
	}
	for _, gate := range f.gates {
		gate.dropChecks.Store(false)
	}
	awaitPath(t, f.ctx, f.endpoints[0], f.endpoints[1], Direct)
	exchange()
}

func TestConnectorConnectivityRejectsOldAttemptEnvelope(t *testing.T) {
	binding := ConnectivityBinding{Revision: testBinding(3)}
	offer := tunnelv1.ConnectorPeerConnectivity{Attempt: 7, UsernameFragment: "offer", Password: "old-password", Candidates: []string{"candidate one"}}
	answer := tunnelv1.ConnectorPeerConnectivity{Attempt: 7, UsernameFragment: "answer", Password: "answer-password"}
	key := connectivityPacketKey([32]byte{1}, binding, offer, answer)
	old := connectivityPacketBinding{key: key, generation: 3, attempt: 7, role: 1}
	frame, err := tunnelv1.SignPeerPacketFrame(tunnelv1.PeerPacket{BindingGeneration: 3, Kind: tunnelv1.PeerData, Sender: 0, Path: Direct, Sequence: 1, Total: 3, Payload: []byte("abc")}, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	packet, err := old.seal(frame)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := old.open(packet); !ok || !bytes.Equal(got, frame) {
		t.Fatal("attempt envelope rejected its own peer frame")
	}
	for _, mutate := range []func(*ConnectivityBinding, *tunnelv1.ConnectorPeerConnectivity, *tunnelv1.ConnectorPeerConnectivity){
		func(b *ConnectivityBinding, _, _ *tunnelv1.ConnectorPeerConnectivity) { b.Revision.Generation++ },
		func(_ *ConnectivityBinding, a, _ *tunnelv1.ConnectorPeerConnectivity) { a.Attempt++ },
		func(_ *ConnectivityBinding, a, _ *tunnelv1.ConnectorPeerConnectivity) { a.Password = "fresh-password" },
		func(_ *ConnectivityBinding, _, b *tunnelv1.ConnectorPeerConnectivity) {
			b.UsernameFragment = "fresh-answer"
		},
		func(_ *ConnectivityBinding, a, _ *tunnelv1.ConnectorPeerConnectivity) {
			a.Candidates = []string{"changed address"}
		},
	} {
		b, a, r := binding, offer, answer
		mutate(&b, &a, &r)
		next := old
		next.key = connectivityPacketKey([32]byte{1}, b, a, r)
		if next.key == key {
			t.Fatal("attempt key did not bind the complete authorized exchange")
		}
		if _, ok := next.open(packet); ok {
			t.Fatal("old attempt frame entered a replacement agent")
		}
	}
	packet[len(packet)-1] ^= 1
	if _, ok := old.open(packet); ok {
		t.Fatal("forged direct packet passed the dispatch filter")
	}
}

func TestConnectorConnectivityRejectsNonIPAndNonUDPCandidates(t *testing.T) {
	for _, encoded := range []string{
		"1 1 udp 1 peer.local 1234 typ host",
		"1 1 tcp 1 192.0.2.1 1234 typ host tcptype passive",
		"1 1 udp 1 192.0.2.1 1234 typ relay raddr 192.0.2.2 rport 5555",
		"1 2 udp 1 192.0.2.1 1234 typ host",
		"1 1 udp 1 0.0.0.0 1234 typ host",
		"1 1 udp 1 224.0.0.1 1234 typ host",
		"1 1 udp 1 255.255.255.255 1234 typ host",
		"1 1 udp 1 ::ffff:224.0.0.1 1234 typ host",
		"1 1 udp 1 ::ffff:255.255.255.255 1234 typ host",
		"1 1 udp 1 192.0.2.1 1234 typ srflx raddr peer.local rport 5555",
	} {
		candidate, err := ice.UnmarshalCandidate(encoded)
		if err == nil && validConnectivityCandidate(candidate) {
			t.Fatal("unsafe candidate was accepted")
		}
	}
}

func TestConnectorConnectivityConsentAndAuthorityFenceBeforeWorkerCleanup(t *testing.T) {
	consent := new(connectivityConsent)
	until := time.Now().Add(time.Minute)
	consent.until.Store(&until)
	local, remote := memoryPair()
	defer remote.Close()
	carrier := connectivityCarrier{Carrier: local, consent: consent, sendAdmit: func([]byte) bool { return false }}
	slot := NewCarrierSlot()
	defer slot.Close()
	if err := slot.install(carrier, consent.valid); err != nil {
		t.Fatal(err)
	}
	e := &Endpoint{ctx: t.Context(), config: Config{Direct: slot, PathTimeout: time.Minute}, bindingActive: true}
	for index := range pathCount {
		e.paths[index] = new(path)
	}
	e.paths[Direct] = &path{carrier: slot, revision: slot.Generation(), alive: true, ack: time.Now()}
	if e.ActivePath() != Direct {
		t.Fatal("fresh direct path was not eligible")
	}
	if err := carrier.Send(t.Context(), []byte("expired authority")); err != nil || len(remote.in) != 0 {
		t.Fatal("direct sender ignored the owner's authority fence", err)
	}
	consent.lost.Store(true)
	if e.ActivePath() == Direct || e.PathHealthy(Direct) {
		t.Fatal("lost ICE consent waited for its worker or packet probe timeout")
	}
}

func TestConnectorConnectivityCancellationInterruptsPartialSignal(t *testing.T) {
	f := newConnectivityFixture(t)
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan error, 1)
	go func() { _, err := readConnectivitySignal(ctx, f.connections[1]); done <- err }()
	out, err := f.connections[0].OpenUniStreamSync(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 100)
	if _, err := out.Write(header[:]); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("partial input succeeded after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("partial signal reader did not join")
	}
	// cancelling only the signaling read must not close the retained connection.
	if errors.Is(context.Cause(f.connections[1].Context()), context.Canceled) {
		t.Fatal("signal cancellation closed the inner connection")
	}
}
