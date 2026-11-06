package service

import (
	"context"
	"crypto/tls"
	"errors"

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

func (p *PeerSession) serveRelayPackets(ctx context.Context) error {
	// relay bridges retain these exact registrations across connector socket
	// replacement. recreating them here would discard replay state and the
	// inner session; publisher connection replacement still retires this owner.
	binding := p.bindingSnapshot()
	paths, err := p.bound.peerCarriers(binding)
	if err != nil {
		return err
	}
	packets, err := peer.New(p.ctx, peer.Config{Key: binding.key, Role: 1, Paths: paths})
	if err != nil {
		closePeerCarriers(paths)
		return err
	}
	defer packets.Close()
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
