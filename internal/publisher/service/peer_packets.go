package service

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"sync"
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

func (b *Bound) peerCarriers(binding PeerBinding, previous [2]*Claimed) (paths [3]peer.Carrier, slots [2]*Claimed, err error) {
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
		if claimed == previous[slot] {
			continue
		}
		paths[slot], err = claimed.packets.Register(peer.PairBinding{Delivery: tunnelv1.PeerDelivery{Pair: binding.delivery, Generation: uint64(binding.generation)}, Key: binding.key, Role: 1, Path: uint8(slot)}, false)
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

func closePeerCarriers(paths [3]peer.Carrier) {
	for _, carrier := range paths {
		if carrier != nil {
			_ = carrier.Close()
		}
	}
}

// ServeRelayPackets registers both current claimed connections, then serves one
// retained inner QUIC session through the existing native admission owner.
func (p *PeerSession) ServeRelayPackets(ctx context.Context) error {
	p.carriersMu.Lock()
	p.bound.mu.Lock()
	if !p.currentLocked() || p.packetStarted || ctx.Err() != nil {
		p.bound.mu.Unlock()
		p.carriersMu.Unlock()
		return ErrPrivateStream
	}
	p.packetStarted = true
	p.packets.Add(1)
	binding := p.binding
	p.bound.mu.Unlock()
	defer p.packets.Done()
	defer p.stop()
	paths, owners, err := p.bound.peerCarriers(binding, [2]*Claimed{})
	if err != nil {
		p.carriersMu.Unlock()
		return err
	}
	for slot := range p.carriers {
		p.carriers[slot] = peer.NewCarrierSlot()
		if paths[slot] != nil {
			_ = p.carriers[slot].Install(paths[slot])
		}
		paths[slot] = p.carriers[slot]
	}
	p.packetOwners = owners
	p.carriersMu.Unlock()
	defer closePeerCarriers(paths)
	direct := p.carriers[peer.Direct]
	packets, err := peer.New(p.ctx, peer.Config{Key: binding.key, Role: 1, Paths: paths})
	if err != nil {
		return err
	}
	defer packets.Close()
	transport := &quic.Transport{Conn: packets}
	defer transport.Close()
	listener, err := transport.Listen(&tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{tunnelv1.ALPN}, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName != p.bound.prepared.managedHostname {
			return nil, ErrPrivateStream
		}
		return p.bound.prepared.currentCertificate()
	}}, &quic.Config{InitialPacketSize: tunnelv1.MaxPeerPacketBytes, DisablePathMTUDiscovery: true, MaxIncomingStreams: maxNativePeerStreams, MaxIncomingUniStreams: 1, MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second})
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
	life, cancel := context.WithCancel(p.ctx)
	var workers sync.WaitGroup
	if p.bound.peerSocket != nil {
		workers.Go(func() {
			_ = peer.ServeConnectivity(life, p.bound.peerSocket, connection, packets, direct, peer.ConnectivityBinding{
				PairID: binding.pairID, DeliveryID: base64.RawURLEncoding.EncodeToString(binding.delivery[:]), Generation: binding.generation,
				RelayAddresses: [2]string{binding.relays[0].RelayAddress, binding.relays[1].RelayAddress},
			}, false, peer.ConnectivityOptions{})
		})
	}
	defer func() { cancel(); workers.Wait() }()
	return p.Serve(ctx, session)
}
