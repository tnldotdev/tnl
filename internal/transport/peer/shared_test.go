package peer

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type sharedDatagramSession struct {
	muxsession.Session
	muxsession.DatagramSession
}

func sharedQUICPair(t *testing.T, ctx context.Context, serverTLS, clientTLS *tls.Config) (sharedDatagramSession, sharedDatagramSession) {
	t.Helper()
	config := muxsession.QUICConfig{Config: &quic.Config{EnableDatagrams: true, InitialPacketSize: 1200, DisablePathMTUDiscovery: true}}
	listener, err := muxsession.ListenConnectorQUIC("127.0.0.1:0", serverTLS, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	left, err := (muxsession.ConnectorQUIC{TLSConfig: clientTLS, Config: config}).Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "peer.test"})
	if err != nil {
		t.Fatal(err)
	}
	right, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	return sharedDatagramSession{left, left.(muxsession.DatagramSession)}, sharedDatagramSession{right, right.(muxsession.DatagramSession)}
}

func TestPeerSharedDatagramsUseOptedInMuxsession(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(strconv.FormatBool(enabled), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			serverTLS, clientTLS := peerTLS(t)
			config := muxsession.QUICConfig{Config: &quic.Config{EnableDatagrams: enabled}}
			listener, err := muxsession.ListenConnectorQUIC("127.0.0.1:0", serverTLS, config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			client, err := (muxsession.ConnectorQUIC{TLSConfig: clientTLS, Config: config}).Connect(ctx,
				muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "peer.test"})
			if err != nil {
				t.Fatal(err)
			}
			server, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
			outbound, clientOK := client.(muxsession.DatagramSession)
			inbound, serverOK := server.(muxsession.DatagramSession)
			if !clientOK || !serverOK || outbound.SupportsDatagrams() != enabled || inbound.SupportsDatagrams() != enabled {
				t.Fatal("muxsession datagram negotiation did not match opt-in")
			}
			if !enabled {
				if _, err := NewSharedDatagrams(ctx, outbound); !errors.Is(err, ErrConfiguration) {
					t.Fatal("shared carrier accepted an ordinary QUIC session", err)
				}
				return
			}
			writer, err := NewSharedDatagrams(ctx, outbound)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := NewSharedDatagrams(ctx, inbound)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = writer.Close(); _ = reader.Close() })
			a, b := sharedBinding(t, 1, RelayA)
			sender, err := writer.Register(a)
			if err != nil {
				t.Fatal(err)
			}
			receiver, err := reader.Register(b)
			if err != nil {
				t.Fatal(err)
			}
			frame := signedFrame(t, a)
			if err := sender.Send(ctx, frame); err != nil {
				t.Fatal(err)
			}
			if got, err := receiver.Receive(ctx); err != nil || !bytes.Equal(got, frame) {
				t.Fatal("shared QUIC session lost its packet", err)
			}
			_ = writer.Close()
			_ = reader.Close()
			if client.Err() != nil || server.Err() != nil {
				t.Fatal("shared packet owner closed its muxsession")
			}
		})
	}
}

func sharedTLSPair(t *testing.T, ctx context.Context, serverTLS, clientTLS *tls.Config) (muxsession.Session, muxsession.Session) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan muxsession.Session, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		s, err := muxsession.AcceptConnectorMuxTLS(ctx, conn, serverTLS, muxsession.TLSYamuxConfig{})
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- s
	}()
	left, err := (muxsession.ConnectorMuxTLS{TLSConfig: clientTLS}).Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "peer.test"})
	if err != nil {
		t.Fatal(err)
	}
	right := <-accepted
	if right == nil {
		t.Fatal("TLS/yamux acceptance failed")
	}
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	return left, right
}

func sharedBinding(t *testing.T, id byte, path uint8) (PairBinding, PairBinding) {
	t.Helper()
	b := PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: [16]byte{id}, Generation: 1}, Kind: NativePeer, Path: path}
	if _, err := rand.Read(b.Key[:]); err != nil {
		t.Fatal(err)
	}
	r := b
	r.Role = 1
	return b, r
}

func signedFrame(t *testing.T, binding PairBinding) []byte {
	t.Helper()
	p := tunnelv1.PeerPacket{Kind: tunnelv1.PeerData, Sender: binding.Role, Path: binding.Path, Sequence: 1, Total: 1, Payload: []byte{1}}
	return signedPacket(t, binding, p)
}

func signedPacket(t *testing.T, binding PairBinding, p tunnelv1.PeerPacket) []byte {
	t.Helper()
	unsigned, err := p.AuthenticatedBytes()
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, binding.Key[:])
	_, _ = mac.Write([]byte(binding.Kind))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(unsigned)
	copy(p.MAC[:], mac.Sum(nil))
	frame, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestPeerSharedDatagramsAcceptOutOfOrderFragmentsOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	serverTLS, clientTLS := peerTLS(t)
	left, right := sharedQUICPair(t, ctx, serverTLS, clientTLS)
	client, err := NewSharedDatagrams(ctx, left)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSharedDatagrams(ctx, right)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	a, b := sharedBinding(t, 1, RelayA)
	sender, err := client.Register(a)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := server.Register(b)
	if err != nil {
		t.Fatal(err)
	}
	fragment := func(number uint8, size int) []byte {
		return signedPacket(t, a, tunnelv1.PeerPacket{Kind: tunnelv1.PeerData, Sender: a.Role, Path: a.Path,
			Sequence: 1, Fragment: number, Total: 1200, Payload: bytes.Repeat([]byte{number + 1}, size)})
	}
	second, first := fragment(1, 200), fragment(0, 1000)
	for _, frame := range [][]byte{second, first} {
		if err := sender.Send(ctx, frame); err != nil {
			t.Fatal(err)
		}
		if got, err := receiver.Receive(ctx); err != nil || !bytes.Equal(got, frame) {
			t.Fatal("out-of-order fragment lost", err)
		}
	}
	for _, frame := range [][]byte{first, second} {
		if err := sender.Send(ctx, frame); err != nil {
			t.Fatal(err)
		}
	}
	quiet, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	defer stop()
	if _, err := receiver.Receive(quiet); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("replayed fragment delivered", err)
	}
}

func TestPeerSharedDatagramsFenceUnknownStaleAndBackpressure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	serverTLS, clientTLS := peerTLS(t)
	left, right := sharedQUICPair(t, ctx, serverTLS, clientTLS)
	client, err := NewSharedDatagrams(ctx, left)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSharedDatagrams(ctx, right)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	a, b := sharedBinding(t, 1, RelayA)
	ca, err := client.Register(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := server.Register(b)
	if err != nil {
		t.Fatal(err)
	}
	frame := signedFrame(t, a)
	if err := ca.Send(ctx, frame); err != nil {
		t.Fatal(err)
	}
	if got, err := cb.Receive(ctx); err != nil || !bytes.Equal(got, frame) {
		t.Fatal("valid packet did not arrive", err)
	}
	// an arbitrary pair ID or a forged MAC must not enter any peer queue.
	for _, mutate := range []func(*tunnelv1.PeerDelivery, []byte){
		func(d *tunnelv1.PeerDelivery, _ []byte) { d.Pair[0] = 9 },
		func(d *tunnelv1.PeerDelivery, _ []byte) { d.Generation++ },
		func(_ *tunnelv1.PeerDelivery, f []byte) { f[len(f)-1]++ },
	} {
		d := a.Delivery
		f := bytes.Clone(frame)
		mutate(&d, f)
		wire, err := d.Seal(tunnelv1.PeerDeliveryDatagram, a.Key, f)
		if err != nil {
			t.Fatal(err)
		}
		if err := left.SendDatagram(ctx, wire); err != nil {
			t.Fatal(err)
		}
	}
	quiet, cancelRead := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancelRead()
	if _, err := cb.Receive(quiet); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("unauthorized packet dispatched", err)
	}
	otherA, otherB := sharedBinding(t, 2, RelayA)
	secondSender, err := client.Register(otherA)
	if err != nil {
		t.Fatal(err)
	}
	secondReceiver, err := server.Register(otherB)
	if err != nil {
		t.Fatal(err)
	}
	for range 3000 {
		if err := ca.Send(ctx, frame); err != nil {
			t.Fatal(err)
		}
	}
	otherFrame := signedFrame(t, otherA)
	// an outer DATAGRAM may be dropped, including in quic-go's receive
	// queue during this flood. packet retries are not application retries.
	// exact scheduler fairness is checked without network loss below.
	for {
		if err := secondSender.Send(ctx, otherFrame); err != nil {
			t.Fatal(err)
		}
		attempt, stop := context.WithTimeout(ctx, 25*time.Millisecond)
		got, err := secondReceiver.Receive(attempt)
		stop()
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			continue
		}
		if err != nil || !bytes.Equal(got, otherFrame) {
			t.Fatal("busy peer starved sibling", err)
		}
		break
	}
	queued, peak, _ := client.QueueStats()
	if queued > sharedGlobalQueue || peak > sharedGlobalQueue {
		t.Fatal("unbounded global queue", queued, peak)
	}
	client.mu.Lock()
	bounded := true
	for _, p := range client.order {
		if len(p.out) > sharedQueuePerPeer {
			bounded = false
		}
	}
	client.mu.Unlock()
	if !bounded {
		t.Fatal("unbounded per-peer queue")
	}
	newA, newB := a, b
	newA.Delivery.Generation++
	newB.Delivery.Generation++
	newCA, err := client.Register(newA)
	if err != nil {
		t.Fatal(err)
	}
	newCB, err := server.Register(newB)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Send(ctx, frame); !errors.Is(err, net.ErrClosed) {
		t.Fatal("old writer survived replacement", err)
	}
	if _, err := cb.Receive(ctx); !errors.Is(err, net.ErrClosed) {
		t.Fatal("old reader survived replacement", err)
	}
	if _, err := client.Register(a); !errors.Is(err, ErrConfiguration) {
		t.Fatal("old generation was re-registered", err)
	}
	stale, err := a.Delivery.Seal(tunnelv1.PeerDeliveryDatagram, a.Key, frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := left.SendDatagram(ctx, stale); err != nil {
		t.Fatal(err)
	}
	staleRead, cancelStale := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancelStale()
	if _, err := newCB.Receive(staleRead); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("late generation delivered", err)
	}
	if err := newCA.Send(ctx, frame); err != nil {
		t.Fatal(err)
	}
	for {
		packet, err := newCB.Receive(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(packet, frame) {
			break
		}
	}
	_ = newCA.Close()
	_ = newCB.Close()
	_ = ca.Close()
	_ = cb.Close()
	_ = secondSender.Close()
	_ = secondReceiver.Close()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if left.Err() != nil || right.Err() != nil {
		t.Fatal("peer owner closed shared QUIC")
	}
}

func TestPeerSharedDatagramsSameKeyCannotRelabelOrReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	serverTLS, clientTLS := peerTLS(t)
	left, right := sharedQUICPair(t, ctx, serverTLS, clientTLS)
	client, err := NewSharedDatagrams(ctx, left)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSharedDatagrams(ctx, right)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	a, remoteA := sharedBinding(t, 1, RelayA)
	b, remoteB := a, remoteA
	b.Delivery.Pair[0], remoteB.Delivery.Pair[0] = 2, 2
	for _, pair := range [][2]PairBinding{{a, remoteA}, {b, remoteB}} {
		if _, err := client.Register(pair[0]); err != nil {
			t.Fatal(err)
		}
		if _, err := server.Register(pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	carrierB := server.peers[b.Delivery.Pair]
	receiver := &SharedDatagramCarrier{owner: server, peer: carrierB}
	frame := signedFrame(t, a)
	original, err := a.Delivery.Seal(tunnelv1.PeerDeliveryDatagram, a.Key, frame)
	if err != nil {
		t.Fatal(err)
	}
	relabel := bytes.Clone(original)
	relabel[1] = 2 // only the unauthenticated-looking pair ID changes.
	wrongGeneration := bytes.Clone(original)
	wrongGeneration[24]++
	stale := b.Delivery
	stale.Generation++
	staleWire, _ := stale.Seal(tunnelv1.PeerDeliveryDatagram, b.Key, frame)
	wrongDirection, _ := b.Delivery.Seal(tunnelv1.PeerDeliveryDatagram, b.Key, signedFrame(t, remoteB))
	wrongMode, _ := b.Delivery.Seal(tunnelv1.PeerDeliveryStream, b.Key, frame)
	for name, wire := range map[string][]byte{
		"relabeled pair": relabel, "relabeled generation": wrongGeneration,
		"stale generation": staleWire, "wrong direction": wrongDirection, "cross mode": wrongMode,
	} {
		if err := left.SendDatagram(ctx, wire); err != nil {
			t.Fatal(name, err)
		}
		quiet, stop := context.WithTimeout(ctx, 30*time.Millisecond)
		_, err := receiver.Receive(quiet)
		stop()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(name, "delivered to other pair", err)
		}
	}
	valid, _ := b.Delivery.Seal(tunnelv1.PeerDeliveryDatagram, b.Key, frame)
	if err := left.SendDatagram(ctx, valid); err != nil {
		t.Fatal(err)
	}
	if got, err := receiver.Receive(ctx); err != nil || !bytes.Equal(got, frame) {
		t.Fatal("valid same-key pair lost", err)
	}
	if err := left.SendDatagram(ctx, valid); err != nil {
		t.Fatal(err)
	}
	quiet, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	defer stop()
	if _, err := receiver.Receive(quiet); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("replay accepted", err)
	}
}

func writeRawIntroduction(t *testing.T, ctx context.Context, session muxsession.Session, header tunnelv1.PeerDelivery, wire []byte) {
	t.Helper()
	stream, err := session.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h, err := header.Header()
	if err != nil {
		t.Fatal(err)
	}
	b := append([]byte(nil), h[:]...)
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(wire)))
	b = append(b, size[:]...)
	b = append(b, wire...)
	if n, err := stream.Write(b); err != nil || n != len(b) {
		t.Fatal("write forged introduction", err)
	}
	_ = stream.Close()
}

func TestPeerSharedStreamsSameKeyIntroductionAndReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	serverTLS, clientTLS := peerTLS(t)
	left, right := sharedTLSPair(t, ctx, serverTLS, clientTLS)
	owner, err := NewSharedStreams(ctx, right)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	a, _ := sharedBinding(t, 1, RelayB)
	b := a
	b.Delivery.Pair[0] = 2
	b.Role = 1
	if _, err := owner.Register(a); err != nil {
		t.Fatal(err)
	}
	pairB, err := owner.Register(b)
	if err != nil {
		t.Fatal(err)
	}
	fromA := signedFrame(t, a)
	aWire, _ := a.Delivery.Seal(tunnelv1.PeerDeliveryStream, a.Key, fromA)
	relabel := bytes.Clone(aWire)
	relabel[1] = 2
	stale := b.Delivery
	stale.Generation++
	staleWire, _ := stale.Seal(tunnelv1.PeerDeliveryStream, b.Key, fromA)
	wrongMode, _ := b.Delivery.Seal(tunnelv1.PeerDeliveryDatagram, b.Key, fromA)
	wrongDirection, _ := b.Delivery.Seal(tunnelv1.PeerDeliveryStream, b.Key, signedFrame(t, b))
	for name, wire := range map[string][]byte{
		"relabeled pair": relabel, "stale generation": staleWire,
		"wrong direction": wrongDirection, "cross mode": wrongMode,
	} {
		writeRawIntroduction(t, ctx, left, b.Delivery, wire)
		quiet, stop := context.WithTimeout(ctx, 30*time.Millisecond)
		_, err := pairB.Accept(quiet)
		stop()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(name, "stream accepted", err)
		}
	}
	valid, _ := b.Delivery.Seal(tunnelv1.PeerDeliveryStream, b.Key, fromA)
	// keep the valid stream open until the first frame is read.
	stream, err := left.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := b.Delivery.Header()
	if _, err := stream.Write(h[:]); err != nil {
		t.Fatal(err)
	}
	if err := tunnelv1.WritePeerDeliveryFrame(stream, valid, tunnelv1.PeerDeliveryStream, b.Key); err != nil {
		t.Fatal(err)
	}
	accepted, err := pairB.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := accepted.Receive(ctx); err != nil || !bytes.Equal(got, fromA) {
		t.Fatal("valid introduction failed", err)
	}
	_ = accepted.Close()
	_ = stream.Close()
	writeRawIntroduction(t, ctx, left, b.Delivery, valid)
	quiet, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	defer stop()
	if _, err := pairB.Accept(quiet); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("replayed introduction accepted", err)
	}
}

func TestPeerSharedStreamsIncompleteIntroductionDoesNotBlockSibling(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	serverTLS, clientTLS := peerTLS(t)
	left, right := sharedTLSPair(t, ctx, serverTLS, clientTLS)
	client, err := NewSharedStreams(ctx, left)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSharedStreams(ctx, right)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	stalled, err := left.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	if _, err := stalled.Write([]byte{tunnelv1.Version}); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Second)
	for len(server.introSlots) == 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if len(server.introSlots) == 0 {
		t.Fatal("incomplete intro was not admitted")
	}
	a, b := sharedBinding(t, 2, RelayB)
	clientPair, err := client.Register(a)
	if err != nil {
		t.Fatal(err)
	}
	serverPair, err := server.Register(b)
	if err != nil {
		t.Fatal(err)
	}
	outgoing, err := clientPair.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer outgoing.Close()
	frame := signedFrame(t, a)
	if err := outgoing.Send(ctx, frame); err != nil {
		t.Fatal(err)
	}
	fast, stop := context.WithTimeout(ctx, 300*time.Millisecond)
	defer stop()
	incoming, err := serverPair.Accept(fast)
	if err != nil {
		t.Fatal("one partial intro blocked sibling", err)
	}
	if got, err := incoming.Receive(fast); err != nil || !bytes.Equal(got, frame) {
		t.Fatal("sibling frame lost", err)
	}
	_ = stalled.Close()
	_ = incoming.Close()
	if err := server.Close(); err != nil {
		t.Fatal("introduction workers not joined", err)
	}
	if len(server.introSlots) != 0 {
		t.Fatal("introduction reader survived shutdown")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if left.Err() != nil || right.Err() != nil {
		t.Fatal("normal peer closure closed outer TLS/yamux")
	}
}

func TestPeerSharedDatagramsBoundRegistrations(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	serverTLS, clientTLS := peerTLS(t)
	left, _ := sharedQUICPair(t, ctx, serverTLS, clientTLS)
	owner, err := NewSharedDatagrams(ctx, left)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	var carriers []Carrier
	for i := 1; i <= sharedMaxPeers; i++ {
		b, _ := sharedBinding(t, byte(i), RelayA)
		c, err := owner.Register(b)
		if err != nil {
			t.Fatal("peer limit below bound", i, err)
		}
		carriers = append(carriers, c)
	}
	extra, _ := sharedBinding(t, 100, RelayA)
	if _, err := owner.Register(extra); !errors.Is(err, ErrConfiguration) {
		t.Fatal("unbounded live peers", err)
	}
	_ = carriers[0].Close()
	extraCarrier, err := owner.Register(extra)
	if err != nil {
		t.Fatal("slot not released", err)
	}
	for _, c := range carriers {
		_ = c.Close()
	}
	// each admission leaves a bounded tombstone even after its carrier closes.
	_ = extraCarrier.Close()
	lastAccepted := 101 + sharedMaxAdmissions - (sharedMaxPeers + 1)
	for i := 101; i < lastAccepted+2; i++ {
		b := extra
		b.Delivery.Pair = [16]byte{byte(i), byte(i >> 8)}
		c, err := owner.Register(b)
		if i < lastAccepted && err != nil {
			t.Fatal("premature admission exhaustion", i, err)
		}
		if i >= lastAccepted && !errors.Is(err, ErrConfiguration) {
			t.Fatal("unbounded tombstones", i, err)
		}
		if c != nil {
			_ = c.Close()
		}
	}
}

type blockedOpenSession struct{ started chan struct{} }

func (s blockedOpenSession) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	close(s.started)
	<-ctx.Done()
	return nil, ctx.Err()
}
func (blockedOpenSession) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (blockedOpenSession) Close() error          { return nil }
func (blockedOpenSession) Done() <-chan struct{} { return nil }
func (blockedOpenSession) Err() error            { return nil }

func TestPeerSharedStreamsJoinBlockedOpen(t *testing.T) {
	session := blockedOpenSession{started: make(chan struct{})}
	owner, err := NewSharedStreams(t.Context(), session)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := sharedBinding(t, 1, RelayB)
	p, err := owner.Register(b)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := p.Open(context.Background()); result <- err }()
	<-session.started
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
		t.Fatal("open survived owner shutdown", err)
	}
}

func TestPeerSharedStreamsRejectUnboundAndPreserveOuterSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	serverTLS, clientTLS := peerTLS(t)
	left, right := sharedTLSPair(t, ctx, serverTLS, clientTLS)
	client, err := NewSharedStreams(ctx, left)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSharedStreams(ctx, right)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	a, b := sharedBinding(t, 1, RelayB)
	ca, err := client.Register(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := server.Register(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []tunnelv1.PeerDelivery{{Pair: [16]byte{9}, Generation: 1}, {Pair: a.Delivery.Pair, Generation: 2}} {
		stream, err := left.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		h, _ := bad.Header()
		if _, err := stream.Write(h[:]); err != nil {
			t.Fatal(err)
		}
		wire, err := bad.Seal(tunnelv1.PeerDeliveryStream, a.Key, signedFrame(t, a))
		if err != nil {
			t.Fatal(err)
		}
		if err := tunnelv1.WritePeerDeliveryFrame(stream, wire, tunnelv1.PeerDeliveryStream, a.Key); err != nil {
			t.Fatal(err)
		}
		_ = stream.Close()
	}
	forged, err := left.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	header, _ := a.Delivery.Header()
	if _, err := forged.Write(header[:]); err != nil {
		t.Fatal(err)
	}
	wrongMAC := signedFrame(t, a)
	wrongMAC[len(wrongMAC)-1]++
	wire, err := a.Delivery.Seal(tunnelv1.PeerDeliveryStream, a.Key, wrongMAC)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnelv1.WritePeerDeliveryFrame(forged, wire, tunnelv1.PeerDeliveryStream, a.Key); err != nil {
		t.Fatal(err)
	}
	_ = forged.Close()
	quiet, cancelRead := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancelRead()
	if _, err := cb.Accept(quiet); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("unbound stream entered pair", err)
	}
	stream, err := ca.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	frame := signedFrame(t, a)
	if err := stream.Send(ctx, frame); err != nil {
		t.Fatal(err)
	}
	accepted, err := cb.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := accepted.Receive(ctx); err != nil || !bytes.Equal(got, frame) {
		t.Fatal("first authenticated frame lost", err)
	}
	if err := stream.Send(ctx, signedFrame(t, b)); !errors.Is(err, tunnelv1.ErrPeerPacket) {
		t.Fatal("wrong direction sent", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if err := accepted.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := accepted.Receive(ctx); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed stream delivered late packet", err)
	}
	_ = ca.Close()
	_ = cb.Close()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if left.Err() != nil || right.Err() != nil {
		t.Fatal("peer streams closed outer TLS/yamux")
	}
}

// the same inner QUIC stream survives a pair-specific QUIC datagram failure
// and moves to a different framed stream on the shared TLS/yamux session.
func TestPeerSharedMixedCarrierKeepsInnerStreamAndSibling(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	serverTLS, clientTLS := peerTLS(t)
	left, right := sharedQUICPair(t, ctx, serverTLS, clientTLS)
	client, err := NewSharedDatagrams(ctx, left)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSharedDatagrams(ctx, right)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	ls, rs := sharedTLSPair(t, ctx, serverTLS, clientTLS)
	clientStreams, err := NewSharedStreams(ctx, ls)
	if err != nil {
		t.Fatal(err)
	}
	serverStreams, err := NewSharedStreams(ctx, rs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientStreams.Close(); _ = serverStreams.Close() })
	var endpoints [2][2]*Endpoint
	var slots [2][2]*CarrierSlot
	var clientPairs, serverPairs [2]*StreamPair
	var gate [2]atomic.Bool
	for i := range 2 {
		a, b := sharedBinding(t, byte(i+1), RelayA)
		ca, err := client.Register(a)
		if err != nil {
			t.Fatal(err)
		}
		cb, err := server.Register(b)
		if err != nil {
			t.Fatal(err)
		}
		flag := &gate[i]
		leftSlot, rightSlot := NewCarrierSlot(), NewCarrierSlot()
		for role, c := range []Carrier{ca, cb} {
			paths := [pathCount]Carrier{&droppableSharedCarrier{Carrier: c, drop: flag}, leftSlot}
			if role == 1 {
				paths[RelayB] = rightSlot
			}
			binding := a
			if role == 1 {
				binding = b
			}
			e, err := New(ctx, Config{Kind: NativePeer, Key: binding.Key, Role: binding.Role, Paths: paths, ProbeInterval: 20 * time.Millisecond, PathTimeout: 150 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			endpoints[i][role] = e
			t.Cleanup(func() { _ = e.Close() })
		}
		slots[i] = [2]*CarrierSlot{leftSlot, rightSlot}
		a.Path, b.Path = RelayB, RelayB
		clientPairs[i], err = clientStreams.Register(a)
		if err != nil {
			t.Fatal(err)
		}
		serverPairs[i], err = serverStreams.Register(b)
		if err != nil {
			t.Fatal(err)
		}
	}
	var connections [2]*quic.Conn
	var streams [2]*quic.Stream
	visitor, visitorSide := tcpPair(t)
	targetSide, target := tcpPair(t)
	var workers sync.WaitGroup
	results := make(chan error, 4)
	workers.Go(func() {
		defer target.CloseWrite()
		var expected byte = 1
		for {
			var b [1]byte
			if _, err := io.ReadFull(target, b[:]); err != nil {
				if errors.Is(err, io.EOF) {
					results <- nil
				} else {
					results <- err
				}
				return
			}
			if b[0] != expected {
				results <- errors.New("target TCP connection lost its counter")
				return
			}
			expected += 2
			if _, err := target.Write(b[:]); err != nil {
				results <- err
				return
			}
		}
	})
	for i := range 2 {
		clientTransport := &quic.Transport{Conn: endpoints[i][0]}
		serverTransport := &quic.Transport{Conn: endpoints[i][1]}
		t.Cleanup(func() { _ = clientTransport.Close(); _ = serverTransport.Close() })
		config := &quic.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true, MaxIdleTimeout: 5 * time.Second, KeepAlivePeriod: 50 * time.Millisecond}
		listener, err := serverTransport.Listen(serverTLS, config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		conn, err := clientTransport.Dial(ctx, endpoints[i][0].RemoteAddr(), clientTLS, config)
		if err != nil {
			t.Fatal("inner QUIC", err)
		}
		peer, err := listener.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.CloseWithError(0, ""); _ = peer.CloseWithError(0, "") })
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		streams[i], connections[i] = stream, conn
		if i == 0 {
			workers.Go(func() { _, err := streamcopy.Copy(visitorSide, &streamConn{Stream: stream}); results <- err })
		}
		workers.Go(func() {
			incoming, err := peer.AcceptStream(ctx)
			if err != nil {
				results <- err
				return
			}
			if i == 0 {
				_, err = streamcopy.Copy(&streamConn{Stream: incoming}, targetSide)
			} else {
				_, err = io.Copy(incoming, incoming)
			}
			results <- err
		})
	}
	t.Cleanup(func() {
		_ = visitor.Close()
		_ = visitorSide.Close()
		_ = target.Close()
		_ = targetSide.Close()
		for _, stream := range streams {
			if stream != nil {
				stream.CancelRead(0)
				stream.CancelWrite(0)
			}
		}
		workers.Wait()
	})
	exchange := func(i int, value byte) {
		t.Helper()
		var connection io.ReadWriter = streams[i]
		if i == 0 {
			connection = visitor
		}
		if _, err := connection.Write([]byte{value}); err != nil {
			t.Fatal(err)
		}
		var got [1]byte
		if _, err := io.ReadFull(connection, got[:]); err != nil || got[0] != value {
			t.Fatal("inner TCP stream changed", got, err)
		}
	}
	exchange(0, 1)
	exchange(1, 2)
	for i := range 2 {
		outgoing, err := clientPairs[i].Open(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := slots[i][0].Install(outgoing); err != nil {
			t.Fatal(err)
		}
		incoming, err := serverPairs[i].Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := slots[i][1].Install(incoming); err != nil {
			t.Fatal(err)
		}
	}
	gate[0].Store(true)
	awaitPath(t, ctx, endpoints[0][0], endpoints[0][1], RelayB)
	exchange(0, 3)
	exchange(1, 4)
	if connections[0].Context().Err() != nil || connections[1].Context().Err() != nil {
		t.Fatal("inner QUIC closed during path change")
	}
	if err := visitor.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, visitor); err != nil {
		t.Fatal("TCP half-close", err)
	}
	for range 3 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	_ = endpoints[0][0].Close()
	_ = endpoints[0][1].Close()
	gate[1].Store(true)
	awaitPath(t, ctx, endpoints[1][0], endpoints[1][1], RelayB)
	exchange(1, 5)
}

type droppableSharedCarrier struct {
	Carrier
	drop *atomic.Bool
}

func (c *droppableSharedCarrier) Send(ctx context.Context, b []byte) error {
	if c.drop.Load() {
		return nil
	}
	return c.Carrier.Send(ctx, b)
}
