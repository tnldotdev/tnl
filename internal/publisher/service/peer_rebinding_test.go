package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func connectorRebindPacketPaths(t *testing.T, ctx context.Context, b *Bound, binding PeerBinding) ([2]peer.Carrier, [2]*connectorPacketWire) {
	t.Helper()
	var paths [2]peer.Carrier
	var wires [2]*connectorPacketWire
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
		b.mu.Lock()
		b.packetSlots[slot] = &Claimed{ref: b.prepared.connectionRef(b.connections[slot]), packets: publisherPackets}
		b.mu.Unlock()
		paths[slot], err = connectorPackets.Register(peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: binding.delivery, Generation: uint64(binding.generation)}, Key: binding.key, Role: 0, Path: uint8(slot)}, true)
		if err != nil {
			t.Fatal(err)
		}
	}
	return paths, wires
}

func awaitPublisherBinding(t *testing.T, ctx context.Context, ready func() bool) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for !ready() {
		select {
		case <-ctx.Done():
			t.Fatal("publisher binding did not reach its expected state", ctx.Err())
		case <-ticker.C:
		}
	}
}

func nextPublisherBinding(binding PeerBinding) PeerBinding {
	binding.generation++
	binding.key[0]++
	binding.state = controlv1.ConnectorPeerPairBindingPrepared
	binding.operation = "ik_" + strings.Repeat("R", 22)
	binding.challenge = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	binding.until, binding.observedAt = time.Now().Add(10*time.Second), time.Now()
	binding.authorityUntil = binding.until
	return binding
}

func TestConnectorPeerRebindingRetainsQUICApplicationTargetAndCapacity(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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
	defer func() { _ = target.Close(); <-acceptDone; targets.Wait() }()
	b, p, verification, opening, _ := connectorPeerFixture(t, target.Addr().String())
	binding := p.bindingSnapshot()
	paths, wires := connectorRebindPacketPaths(t, ctx, b, binding)
	var slots [2]*peer.CarrierSlot
	for index, path := range paths {
		slots[index] = peer.NewCarrierSlot()
		if err := slots[index].Install(path); err != nil {
			t.Fatal(err)
		}
	}
	packets, err := peer.New(ctx, peer.Config{Key: binding.sessionKey, Role: 0, Binding: binding.revision(), Paths: [2]peer.Carrier{slots[0], slots[1]}})
	if err != nil {
		t.Fatal(err)
	}
	defer packets.Close()
	served := make(chan error, 1)
	go func() { served <- p.Serve(ctx) }()
	defer func() { p.Close(); <-served }()
	awaitPeerSignal(t, ctx, p.ready)
	transport := &quic.Transport{Conn: packets}
	defer transport.Close()
	trust := verification.Clone()
	trust.NextProtos = []string{muxsession.ALPN}
	connection, err := transport.Dial(ctx, packets.RemoteAddr(), trust, tunnel.ConnectorQUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	inner, err := muxsession.AdoptQUIC(connection)
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	control := connectorControl(t, ctx, inner)
	entry := opening("B")
	traffic := openPermissionVisitor(t, ctx, inner, trust, entry)
	a := permissionAdmission(t, b, p, entry.VisitorConnectionID)
	echo := func(text string) {
		t.Helper()
		_ = traffic.SetDeadline(time.Now().Add(time.Second))
		if _, err := io.WriteString(traffic, text); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(text))
		if _, err := io.ReadFull(traffic, got); err != nil || string(got) != text {
			t.Fatal("retained transcript changed", err)
		}
	}
	echo("before")
	permissionUntil, err := a.CheckUse(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// expire only delivery. owner and application permission remain current.
	b.mu.Lock()
	p.lease.until = time.Now().Add(20 * time.Millisecond)
	close(p.changed)
	p.changed = make(chan struct{})
	b.mu.Unlock()
	awaitPublisherBinding(t, ctx, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return !p.deliveryActive })
	for _, wire := range wires {
		_ = wire.Close()
	}
	b.mu.Lock()
	retained := p.currentLocked() && b.reservedStreams == 1 && len(p.seen) == 1 && !a.retiring
	b.mu.Unlock()
	if !retained || accepted.Load() != 1 {
		t.Fatal("delivery loss ended retained ownership")
	}
	if _, err := a.CheckUse(ctx); err != nil {
		t.Fatal("delivery loss ended application permission", err)
	}
	pending := nextPublisherBinding(binding)
	packets.SuspendBinding()
	if err := packets.StageBinding(pending.revision()); err != nil {
		t.Fatal(err)
	}
	paths, _ = connectorRebindPacketPaths(t, ctx, b, pending)
	if err := p.stageBinding(pending); err != nil {
		t.Fatal(err)
	}
	for slot, path := range paths {
		if err := packets.InstallBindingCarrier(pending.revision(), slot, path); err != nil {
			t.Fatal(err)
		}
	}
	awaitPublisherBinding(t, ctx, func() bool {
		_, left := packets.BindingProofs(pending.revision())
		_, right := p.packets.BindingProofs(pending.revision())
		return left && right
	})
	active := pending
	active.state = controlv1.ConnectorPeerPairBindingActive
	active.source = netip.MustParseAddr("192.0.2.2")
	if err := p.activateBinding(active); err != nil {
		t.Fatal(err)
	}
	if err := packets.ActivateBinding(active.revision()); err != nil {
		t.Fatal(err)
	}
	echo("after")
	after, err := a.CheckUse(ctx)
	if err != nil || !after.Equal(permissionUntil) {
		t.Fatal("binding activation changed application permission", err)
	}
	b.mu.Lock()
	retained = p.currentLocked() && b.reservedStreams == 1 && b.connectorPending == 0 && len(p.seen) == 1 && !a.retiring && a.entry.DeliveryGeneration == active.generation
	current := a.entry
	b.mu.Unlock()
	if !retained || accepted.Load() != 1 || connection.Context().Err() != nil {
		t.Fatal("rebind replaced inner QUIC, application, target, history, or capacity")
	}
	message, err := tunnelv1.ConnectorPeerProofMessage(current, nil)
	if err != nil {
		t.Fatal(err)
	}
	current.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)), message))
	update := signedPermissionUpdate(t, b, p, current, 1, time.Now().Add(2*time.Minute))
	if err := control.Renew(ctx, update); err != nil {
		t.Fatal("rebind replaced the shared permission-control stream", err)
	}
	echo("renewed")
}

func TestConnectorPeerPendingExpiryAndFailedStageRetireOnlyThatRevision(t *testing.T) {
	for _, boundary := range []string{"pending expiry", "partial installation"} {
		t.Run(boundary, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			b, p, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
			binding := p.bindingSnapshot()
			_, _ = connectorRebindPacketPaths(t, ctx, b, binding)
			served := make(chan error, 1)
			go func() { served <- p.Serve(ctx) }()
			defer func() { p.Close(); <-served }()
			awaitPeerSignal(t, ctx, p.ready)
			pending := nextPublisherBinding(binding)
			if boundary == "pending expiry" {
				pending.until = time.Now().Add(30 * time.Millisecond)
				_, _ = connectorRebindPacketPaths(t, ctx, b, pending)
				if err := p.stageBinding(pending); err != nil {
					t.Fatal(err)
				}
			} else {
				b.mu.Lock()
				b.packetSlots[0] = nil
				b.mu.Unlock()
				if err := p.stageBinding(pending); err == nil {
					t.Fatal("missing carrier installed a pending binding")
				}
			}
			awaitPublisherBinding(t, ctx, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return p.pendingRetired })
			b.mu.Lock()
			retained := p.currentLocked() && !p.deliveryActive && !p.pendingInstalled && p.highwater == pending.generation
			changed := p.changed
			b.mu.Unlock()
			if !retained {
				t.Fatal("retiring delivery lost the owner or revision high-water")
			}
			if _, ready := p.packets.BindingProofs(pending.revision()); ready {
				t.Fatal("retired pending binding kept producing usable path proofs")
			}
			if err := p.stageBinding(pending); err == nil {
				t.Fatal("retired pending revision resumed")
			}
			candidate := controlv1.ConnectorPeerPairCandidate{PairId: pending.pairID, DeliveryGeneration: pending.generation}
			if b.peerNeedsPreparation(candidate) {
				t.Fatal("retired pending operation kept scheduling delivery work")
			}
			timer := time.NewTimer(10 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-changed:
				t.Fatal("retired pending deadline kept waking the owner watch")
			case <-timer.C:
			}
			newer := nextPublisherBinding(pending)
			newer.operation = "ik_" + strings.Repeat("N", 22)
			_, _ = connectorRebindPacketPaths(t, ctx, b, newer)
			if err := p.stageBinding(newer); err != nil {
				t.Fatal("new authorized revision could not follow retired delivery", err)
			}
			b.mu.Lock()
			retained = p.currentLocked() && p.pendingInstalled && !p.pendingRetired && p.highwater == newer.generation
			b.mu.Unlock()
			if !retained {
				t.Fatal("new stage changed owner rather than replacing delivery")
			}
		})
	}
}

func TestConnectorPeerPacketAdmissionDoesNotWaitForDeadlineWatch(t *testing.T) {
	for _, boundary := range []string{"delivery", "installation", "owner", "pending", "prepared data"} {
		t.Run(boundary, func(t *testing.T) {
			b, p, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
			binding := p.bindingSnapshot()
			packet := tunnelv1.PeerPacket{Kind: tunnelv1.PeerData, BindingGeneration: uint64(binding.generation)}
			if !b.admitPeerPacket(binding.pairID, binding.generation, packet) {
				t.Fatal("current packet was not admitted")
			}
			b.mu.Lock()
			switch boundary {
			case "delivery":
				p.lease.until = time.Now().Add(-time.Second)
			case "installation":
				p.installedUntil = time.Now().Add(-time.Second)
			case "owner":
				p.owner.until = time.Now().Add(-time.Second)
			default:
				pending := nextPublisherBinding(binding)
				binding = pending
				p.pending, p.highwater = &pending, pending.generation
				packet.BindingGeneration = uint64(pending.generation)
				if boundary == "pending" {
					p.pending.until = time.Now().Add(-time.Second)
				}
			}
			b.mu.Unlock()
			if b.admitPeerPacket(binding.pairID, binding.generation, packet) {
				t.Fatal("packet admission waited for the deadline watch to fence invalid data")
			}
			packet.Kind = tunnelv1.PeerProbe
			if got := b.admitPeerPacket(binding.pairID, binding.generation, packet); got != (boundary == "prepared data") {
				t.Fatal("prepared probes bypassed a deadline or lost their staging path")
			}
		})
	}
}
