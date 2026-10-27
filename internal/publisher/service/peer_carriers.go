package service

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// publisherPeerPackets borrows one claimed publisher connection. only the run
// owner supplies independently control-authorized pair registrations.
type publisherPeerPackets struct {
	ctx        context.Context
	cancel     context.CancelFunc
	datagrams  *peer.SharedDatagrams
	streams    *peer.SharedStreams
	dispatcher *tunnel.ServiceStreamDispatcher
	done       chan struct{}
	once       sync.Once
}

// check QUIC's packet capability before the tunnel hello can consume a
// single-use publisher assignment. TCP remains eligible in the same race.
func requirePublisherPeerDatagrams(connector muxsession.Connector) muxsession.Connector {
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
		datagrams, ok := session.(muxsession.DatagramSession)
		if !ok || !datagrams.SupportsDatagrams() {
			return nil, errors.Join(ErrPrivateStream, peer.ErrConfiguration, session.Close())
		}
		return session, nil
	})
}

func newPublisherPeerPackets(parent context.Context, session *tunnel.Session) (*publisherPeerPackets, error) {
	outer, err := session.BorrowServicePublisherTransport()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	p := &publisherPeerPackets{ctx: ctx, cancel: cancel, done: make(chan struct{})}
	if datagrams, ok := outer.(muxsession.DatagramSession); ok {
		p.datagrams, err = peer.NewSharedDatagrams(ctx, datagrams)
	} else {
		p.streams, err = peer.NewDispatchedSharedStreams(ctx, outer)
		if err == nil {
			p.dispatcher, err = tunnel.NewServiceStreamDispatcher(ctx, session, p.streams)
		}
	}
	if err != nil {
		cancel()
		if p.streams != nil {
			_ = p.streams.Close()
		}
		return nil, err
	}
	go func() {
		defer close(p.done)
		select {
		case <-outer.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	return p, nil
}

func (p *publisherPeerPackets) register(binding peer.PairBinding) (peer.Carrier, error) {
	if err := p.ctx.Err(); err != nil {
		return nil, err
	}
	if p.datagrams != nil {
		return p.datagrams.Register(binding)
	}
	registration, err := p.streams.Register(binding)
	if err != nil {
		return nil, err
	}
	return registration.Carrier(false), nil
}

func (p *publisherPeerPackets) Close() {
	p.once.Do(func() {
		p.cancel()
		if p.dispatcher != nil {
			_ = p.dispatcher.Close()
		}
		if p.datagrams != nil {
			_ = p.datagrams.Close()
		}
		if p.streams != nil {
			_ = p.streams.Close()
		}
		<-p.done
	})
}

func (b *Bound) peerCarriers(binding PeerBinding) (paths [3]peer.Carrier, err error) {
	b.mu.Lock()
	if !b.peerBindingCurrentLocked(binding, time.Now()) {
		b.mu.Unlock()
		return paths, ErrPrivateStream
	}
	slots := b.packetSlots
	for slot, claimed := range slots {
		if claimed == nil || claimed.packets == nil || claimed.ref.PublisherConnectionID != binding.relays[slot].PublisherConnectionId ||
			claimed.ref.ConnectionAssignmentRevision != uint64(binding.relays[slot].AssignmentRevision) {
			b.mu.Unlock()
			return paths, ErrPrivateStream
		}
	}
	b.mu.Unlock()
	defer func() {
		if err != nil {
			closePeerCarriers(paths)
		}
	}()
	for slot, claimed := range slots {
		paths[slot], err = claimed.packets.register(peer.PairBinding{
			Delivery: tunnelv1.PeerDelivery{Pair: binding.deliveryID, Generation: uint64(binding.generation)},
			Key:      binding.key, Kind: peer.NativePeer, Role: 1, Path: uint8(slot),
		})
		if err != nil {
			return paths, err
		}
	}
	b.mu.Lock()
	current := b.peerBindingCurrentLocked(binding, time.Now()) && b.packetSlots == slots
	b.mu.Unlock()
	if !current {
		return paths, ErrPrivateStream
	}
	return paths, nil
}

func closePeerCarriers(paths [3]peer.Carrier) {
	for _, path := range paths {
		if path != nil {
			_ = path.Close()
		}
	}
}
