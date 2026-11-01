package service

import (
	"context"
	"crypto/tls"
	"errors"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
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

func (b *Bound) peerCarriers(binding PeerBinding) (paths [2]peer.Carrier, err error) {
	b.mu.Lock()
	current := b.peerCurrentLocked(binding) && b.peerRelaysCurrentLocked(binding)
	slots := b.packetSlots
	for slot, claimed := range slots {
		current = current && claimed != nil && claimed.ref.PublisherConnectionID == binding.relays[slot].PublisherConnectionId && claimed.ref.ConnectionAssignmentRevision == uint64(binding.relays[slot].AssignmentRevision)
	}
	b.mu.Unlock()
	if !current {
		return paths, ErrPrivateStream
	}
	defer func() {
		if err != nil {
			closePeerCarriers(paths)
		}
	}()
	for slot, claimed := range slots {
		paths[slot], err = claimed.packets.Register(peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: binding.delivery, Generation: uint64(binding.generation)}, Key: binding.key, Role: 1, Path: uint8(slot)}, false)
		if err != nil {
			return paths, err
		}
	}
	b.mu.Lock()
	current = b.peerCurrentLocked(binding) && b.peerRelaysCurrentLocked(binding) && b.packetSlots == slots
	b.mu.Unlock()
	if !current {
		return paths, ErrPrivateStream
	}
	return paths, nil
}

func closePeerCarriers(paths [2]peer.Carrier) {
	for _, carrier := range paths {
		if carrier != nil {
			_ = carrier.Close()
		}
	}
}

// ServeRelayPackets registers both current claimed connections, then serves one
// retained inner QUIC session through the existing connector admission owner.
func (p *PeerSession) ServeRelayPackets(ctx context.Context) error {
	p.bound.mu.Lock()
	if !p.currentLocked() || p.packetStarted || ctx.Err() != nil {
		p.bound.mu.Unlock()
		return ErrPrivateStream
	}
	p.packetStarted = true
	p.packets.Add(1)
	binding := p.binding
	p.bound.mu.Unlock()
	defer p.packets.Done()
	defer p.stop()
	paths, err := p.bound.peerCarriers(binding)
	if err != nil {
		return err
	}
	defer closePeerCarriers(paths)
	packets, err := peer.New(p.ctx, peer.Config{Key: binding.key, Role: 1, Paths: paths})
	if err != nil {
		return err
	}
	defer packets.Close()
	transport := &quic.Transport{Conn: packets}
	defer transport.Close()
	listener, err := transport.Listen(&tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{muxsession.ALPN}, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName != p.bound.prepared.managedHostname {
			return nil, ErrPrivateStream
		}
		return p.bound.prepared.currentCertificate()
	}}, &quic.Config{InitialPacketSize: tunnelv1.MaxPeerPacketBytes, DisablePathMTUDiscovery: true, MaxIncomingStreams: maxConnectorPeerStreams, MaxIncomingUniStreams: 1, MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second})
	if err != nil {
		return err
	}
	defer listener.Close()
	close(p.packetReady)
	connection, err := listener.Accept(p.ctx)
	if err != nil {
		return err
	}
	_ = listener.Close()
	session, err := muxsession.AdoptQUIC(connection)
	if err != nil {
		return err
	}
	return p.Serve(ctx, session)
}
