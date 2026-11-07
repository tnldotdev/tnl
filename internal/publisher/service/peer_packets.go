package service

import (
	"context"
	"crypto/tls"
	"errors"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/security/tlspolicy"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// reject an unnegotiated QUIC candidate before its single-use publisher hello.
func requirePeerDatagrams(connector muxsession.Connector) muxsession.Connector {
	return muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		if connector == nil {
			return nil, ErrPrivateStream
		}
		session, err := connector.Connect(ctx, endpoint)
		if err != nil {
			return nil, err
		}
		if session == nil {
			return nil, ErrPrivateStream
		}
		if packets, ok := session.(muxsession.DatagramSession); !ok || !packets.SupportsDatagrams() {
			return nil, errors.Join(peer.ErrConfiguration, session.Close())
		}
		return session, nil
	})
}

func (b *Bound) peerCarriers(binding PeerBinding) (paths [2]peer.Carrier, slots [2]*Claimed, err error) {
	b.mu.Lock()
	current := b.peerCurrentLocked(binding) && b.peerRelaysCurrentLocked(binding)
	slots = b.packetSlots
	for slot, claimed := range slots {
		current = current && claimed != nil && claimed.ref.PublisherConnectionID == binding.relays[slot].PublisherConnectionId && claimed.ref.ConnectionAssignmentRevision == uint64(binding.relays[slot].AssignmentRevision)
	}
	b.mu.Unlock()
	if !current {
		return paths, slots, ErrPrivateStream
	}
	defer func() {
		if err != nil {
			closePeerCarriers(paths)
		}
	}()
	for slot, claimed := range slots {
		paths[slot], err = claimed.packets.Register(peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: binding.delivery, Generation: uint64(binding.generation)}, Key: binding.key, Role: 1, Path: uint8(slot), AdmitPacket: func(packet tunnelv1.PeerPacket) bool {
			return b.admitPeerPacket(binding.pairID, binding.generation, packet)
		}}, false)
		if err != nil {
			return paths, slots, err
		}
	}
	b.mu.Lock()
	current = b.peerCurrentLocked(binding) && b.peerRelaysCurrentLocked(binding) && b.packetSlots == slots
	b.mu.Unlock()
	if !current {
		return paths, slots, ErrPrivateStream
	}
	return paths, slots, nil
}

// reject expired authority and prepared data before shared queues, independently
// of when the owner watch gets CPU time to detach an expired registration.
func (b *Bound) admitPeerPacket(pairID string, generation int64, packet tunnelv1.PeerPacket) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	p := b.connectorPeers[pairID]
	if p == nil || !p.currentLocked() || packet.BindingGeneration != uint64(generation) {
		return false
	}
	if p.pending != nil {
		return p.deliveryState != peerDeliveryRetired && p.pending.generation == generation && p.pending.until.After(time.Now()) &&
			(packet.Kind == tunnelv1.PeerProbe || packet.Kind == tunnelv1.PeerProbeReply)
	}
	return p.network.generation == generation && p.deliveryCurrentLocked()
}

func closePeerCarriers(paths [2]peer.Carrier) {
	for _, carrier := range paths {
		if carrier != nil {
			_ = carrier.Close()
		}
	}
}

func (p *PeerSession) serveRelayPackets(ctx context.Context) error {
	// the endpoint and its slots outlive individual registrations. rebinding
	// never constructs another listener, transport, or permission-control stream.
	binding := p.bindingSnapshot()
	paths, slots, err := p.bound.peerCarriers(binding)
	if err != nil {
		return err
	}
	var pathSlots [2]*peer.CarrierSlot
	for index, path := range paths {
		pathSlots[index] = peer.NewCarrierSlot()
		if err := pathSlots[index].Install(path); err != nil {
			closePeerCarriers(paths)
			return err
		}
	}
	packets, err := peer.New(p.ctx, peer.Config{Key: binding.sessionKey, Role: 1, Binding: binding.revision(), Paths: [2]peer.Carrier{pathSlots[0], pathSlots[1]}})
	if err != nil {
		closePeerCarriers(paths)
		return err
	}
	defer packets.Close()
	p.bound.mu.Lock()
	p.packets, p.packetPaths, p.deliverySlots = packets, pathSlots, slots
	current := p.currentLocked() && p.bound.peerRelaysCurrentLocked(binding) && p.bound.packetSlots == slots
	p.bound.mu.Unlock()
	if !current {
		return ErrPrivateStream
	}
	transport := &quic.Transport{Conn: packets}
	defer transport.Close()
	listener, err := transport.Listen(tlspolicy.RequirePostQuantum(&tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{muxsession.ALPN}, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName != p.bound.prepared.managedHostname {
			return nil, ErrPrivateStream
		}
		return p.bound.prepared.currentCertificate()
	}}), tunnel.ConnectorQUICConfig())
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := p.markReady(ctx); err != nil {
		return err
	}
	connection, err := listener.Accept(p.ctx)
	if err != nil {
		return err
	}
	_ = listener.Close()
	session, err := muxsession.AdoptQUIC(connection)
	if err != nil {
		return err
	}
	return p.serveSession(session)
}

func (p *PeerSession) markReady(ctx context.Context) error {
	p.bound.mu.Lock()
	defer p.bound.mu.Unlock()
	if ctx.Err() != nil || !p.currentLocked() {
		return ErrPrivateStream
	}
	close(p.ready)
	return nil
}
