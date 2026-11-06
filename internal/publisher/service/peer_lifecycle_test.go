package service

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorPeerSetupCancellationJoinsWithoutLateReadiness(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, p, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
	setup, stopSetup := context.WithCancel(ctx)
	defer stopSetup()
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	releaseSetup := sync.OnceFunc(func() { close(release) })
	defer releaseSetup()
	served := make(chan error, 1)
	go func() {
		served <- p.serve(setup, func() error {
			close(entered)
			<-p.ctx.Done()
			close(canceled)
			<-release
			return p.markReady(setup)
		})
	}()
	awaitPeerSignal(t, ctx, entered)
	stopSetup()
	awaitPeerSignal(t, ctx, canceled)
	closed := make(chan struct{}, 2)
	for range 2 {
		go func() { p.Close(); closed <- struct{}{} }()
	}
	select {
	case <-closed:
		t.Fatal("close returned before entered setup joined")
	default:
	}
	releaseSetup()
	if err := <-served; !errors.Is(err, ErrPrivateStream) {
		t.Fatal("canceled setup published readiness", err)
	}
	for range 2 {
		awaitPeerSignal(t, ctx, closed)
	}
	select {
	case <-p.ready:
		t.Fatal("setup cancellation published packet readiness late")
	default:
	}
	if err := p.Serve(ctx); !errors.Is(err, ErrPrivateStream) {
		t.Fatal("retired setup restarted serving", err)
	}
}

func TestConnectorPeerSetupFailureAndUnstartedCloseRetainReplayFence(t *testing.T) {
	for _, start := range []bool{false, true} {
		t.Run(map[bool]string{false: "close reservation", true: "failed packet setup"}[start], func(t *testing.T) {
			b, p, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
			binding := p.bindingSnapshot()
			if start {
				if err := p.Serve(t.Context()); !errors.Is(err, ErrPrivateStream) {
					t.Fatal("setup without installed packet slots succeeded", err)
				}
			}
			p.Close()
			awaitPeerSignal(t, t.Context(), p.done)
			if err := p.Renew(binding); !errors.Is(err, ErrPrivateStream) {
				t.Fatal("retired owner renewed", err)
			}
			if replacement, err := b.BindPeer(t.Context(), binding); err == nil {
				replacement.Close()
				t.Fatal("closed pair was rebound without retaining its replay fence")
			}
			select {
			case <-p.ready:
				t.Fatal("failed or unstarted setup advertised readiness")
			default:
			}
		})
	}
}

func TestConnectorPeerRenewalChangesOnlyLeaseEvidence(t *testing.T) {
	b, p, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
	before := p.bindingSnapshot()
	b.mu.Lock()
	p.installedUntil = before.until
	b.mu.Unlock()
	next := before
	next.until = next.until.Add(time.Minute)
	next.authorityUntil = next.authorityUntil.Add(time.Minute)
	if err := p.Renew(next); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if p.identity != before.peerIdentity || p.lease != next.peerLease || p.installedUntil != before.until {
		t.Fatal("renewal changed immutable identity or synthesized publisher installation evidence")
	}
}

func TestConnectorPeerCloseKeepsPendingChargeUntilPhysicalCloseJoins(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	b, p, verification, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
	client, server := connectorInnerPair(t, ctx, verification)
	entered, release := make(chan struct{}), make(chan struct{})
	releaseClose := sync.OnceFunc(func() { close(release) })
	defer releaseClose()
	served := make(chan error, 1)
	go func() {
		served <- serveConnectorInner(ctx, p, &heldConnectorSessionClose{Session: server, entered: entered, release: release})
	}()
	connectorControl(t, ctx, client)
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	// an incomplete opening owns pending setup, but no visitor permission or C.
	if _, err := stream.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		b.mu.Lock()
		pending := b.connectorPending
		b.mu.Unlock()
		if pending == 1 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("inner stream did not reserve pending setup", ctx.Err())
		case <-ticker.C:
		}
	}
	closed := make(chan struct{})
	go func() { p.Close(); close(closed) }()
	awaitPeerSignal(t, ctx, entered)
	b.mu.Lock()
	active, pending := b.reservedStreams, b.connectorPending
	// even an elapsed tombstone cannot retire history while physical work remains.
	p.replayUntil = time.Now().Add(-time.Second)
	binding := p.bindingLocked()
	b.mu.Unlock()
	if active != 0 || pending != 1 {
		t.Fatal("pending charge was returned before physical close joined", active, pending)
	}
	if replacement, err := b.BindPeer(ctx, binding); err == nil {
		replacement.Close()
		t.Fatal("unjoined owner was pruned from the replay fence")
	}
	select {
	case <-p.done:
		t.Fatal("serving completed before pending physical close joined")
	default:
	}
	releaseClose()
	awaitPeerSignal(t, ctx, closed)
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.connectorPending != 0 || len(p.streams) != 0 {
		t.Fatal("joined pending setup leaked its charge or worker")
	}
}

// these two datagram wires replace only the borrowed outer transports. the
// publisher still registers both carriers and serves a real retained inner QUIC.
type connectorPacketWire struct {
	muxsession.Session
	ctx     context.Context
	cancel  context.CancelFunc
	in, out chan []byte
}

func (w *connectorPacketWire) SupportsDatagrams() bool { return true }
func (w *connectorPacketWire) Done() <-chan struct{}   { return w.ctx.Done() }
func (w *connectorPacketWire) Err() error              { return w.ctx.Err() }
func (w *connectorPacketWire) Close() error            { w.cancel(); return nil }
func (w *connectorPacketWire) SendDatagram(ctx context.Context, packet []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-w.ctx.Done():
		return net.ErrClosed
	case w.out <- append([]byte(nil), packet...):
		return nil
	}
}
func (w *connectorPacketWire) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-w.ctx.Done():
		return nil, net.ErrClosed
	case packet := <-w.in:
		return packet, nil
	}
}

func TestConnectorPeerServingOwnsFixedCarriersAndRetainedInnerSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	var targets sync.WaitGroup
	var accepted atomic.Int64
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			targets.Go(func() { defer conn.Close(); _, _ = io.Copy(conn, conn) })
		}
	}()
	b, p, verification, opening, _ := connectorPeerFixture(t, target.Addr().String())
	binding := p.bindingSnapshot()
	var wires [2]*connectorPacketWire
	var paths [2]peer.Carrier
	for slot := range 2 {
		life, stop := context.WithCancel(ctx)
		t.Cleanup(stop)
		left, right := make(chan []byte, 64), make(chan []byte, 64)
		wires[slot] = &connectorPacketWire{ctx: life, cancel: stop, in: left, out: right}
		remote := &connectorPacketWire{ctx: life, cancel: stop, in: right, out: left}
		publisherPackets, err := peer.NewSharedSession(ctx, wires[slot])
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = publisherPackets.Close() })
		connectorPackets, err := peer.NewSharedSession(ctx, remote)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = connectorPackets.Close() })
		b.packetSlots[slot] = &Claimed{ref: b.prepared.connectionRef(b.connections[slot]), packets: publisherPackets}
		paths[slot], err = connectorPackets.Register(peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: binding.delivery, Generation: uint64(binding.generation)}, Key: binding.key, Role: 0, Path: uint8(slot)}, true)
		if err != nil {
			t.Fatal(err)
		}
	}
	served := make(chan error, 1)
	go func() { served <- p.Serve(ctx) }()
	defer p.Close()
	awaitPeerSignal(t, ctx, p.ready)
	packets, err := peer.New(ctx, peer.Config{Key: binding.key, Role: 0, Paths: paths})
	if err != nil {
		t.Fatal(err)
	}
	defer packets.Close()
	transport := &quic.Transport{Conn: packets}
	defer transport.Close()
	trust := verification.Clone()
	trust.NextProtos = []string{muxsession.ALPN}
	connection, err := transport.Dial(ctx, packets.RemoteAddr(), trust, tunnel.ConnectorQUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	if state := connection.ConnectionState().TLS; state.Version != tls.VersionTLS13 || state.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("inner publisher connection negotiated TLS %x with %s", state.Version, state.CurveID)
	}
	inner, err := muxsession.AdoptQUIC(connection)
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	connectorControl(t, ctx, inner)
	stream, err := inner.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tunnelv1.WriteConnectorPeerVisitorOpening(stream, opening("T"), nil); err != nil {
		t.Fatal(err)
	}
	secured := connectorVisitorTLS(stream, verification, opening("T").VisitorConnectionID)
	defer secured.Close()
	_ = secured.SetDeadline(time.Now().Add(3 * time.Second))
	echo := func(text string) {
		t.Helper()
		if _, err := io.WriteString(secured, text); err != nil {
			t.Fatal(err)
		}
		data := make([]byte, len(text))
		if _, err := io.ReadFull(secured, data); err != nil || string(data) != text {
			t.Fatal("retained target transcript changed", string(data), err)
		}
	}
	echo("before failover")
	_ = wires[0].Close()
	echo("same inner stream and target after failover")
	if accepted.Load() != 1 {
		t.Fatal("fixed-carrier failover reopened the target", accepted.Load())
	}
	_ = wires[1].Close()
	terminal, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	awaitPeerSignal(t, terminal, p.done)
	<-served
	b.mu.Lock()
	active, pending, history := b.reservedStreams, b.connectorPending, len(p.seen)
	b.mu.Unlock()
	if active != 0 || pending != 0 || history != 1 {
		t.Fatal("terminal carriers leaked admissions or discarded replay history", active, pending, history)
	}
	if _, err := b.BindPeer(ctx, binding); !errors.Is(err, ErrPrivateStream) {
		t.Fatal("terminal owner transferred its replay history to a replacement", err)
	}
	_ = target.Close()
	awaitPeerSignal(t, ctx, acceptDone)
	targets.Wait()
}

func awaitPeerSignal(t *testing.T, ctx context.Context, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-ctx.Done():
		t.Fatal("peer lifecycle did not complete", ctx.Err())
	}
}
