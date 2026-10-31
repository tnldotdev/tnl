package stream

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// the fixture supplies authority replies and native packet acceptance. the
// production connector still owns pair preparation, carrier races, inner QUIC,
// openings, TLS, renewal and cleanup. publisher policy is covered by its owner
// and the real daemon consumer tests, not reimplemented here.
type fixtureNativePeer struct {
	owner   string
	pair    controlv1.NativePeerPair
	key     [32]byte
	paths   [2]chan peer.Carrier
	nonces  [2][]byte
	seen    map[string]struct{}
	session muxsession.Session
}

type fixtureTLSGate struct {
	entered, release chan struct{}
	once             sync.Once
}

func fixtureDatagramConfig() *quic.Config { return &quic.Config{EnableDatagrams: true} }

func (p *fixtureNativePeer) receipt(slot int) tunnelv1.NativePairLegAccepted {
	return tunnelv1.NativePairLegAccepted{PairID: p.pair.PairId, DeliveryID: p.pair.DeliveryId, DeliveryGeneration: p.pair.DeliveryGeneration,
		ConnectionSlot: slot, SourceIP: "127.0.0.1", ObservedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
}

func (f *connectorFixture) PrepareNativePeerPair(ctx context.Context, service string, body controlv1.NativePeerPairRequest) (controlv1.NativePeerPair, error) {
	message, err := controlv1.NativePeerPairProofMessage(service, body)
	signature, decodeErr := base64.RawURLEncoding.DecodeString(body.Signature)
	if err != nil || decodeErr != nil || !ed25519.Verify(f.device.PublicKey, message, signature) || !visitorsubject.Equal(body.Subject, f.device.Subject) {
		return controlv1.NativePeerPair{}, ErrServiceConnection
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if ctx.Err() != nil || f.ctx.Err() != nil {
		return controlv1.NativePeerPair{}, context.Canceled
	}
	for _, p := range f.peers {
		if p.owner == body.IdempotencyKey {
			result := p.pair
			result.ObservedAt, result.ExpiresAt = time.Now(), f.expires
			return result, nil
		}
	}
	id, err := opaqueid.New("npp_")
	if err != nil {
		return controlv1.NativePeerPair{}, err
	}
	p := &fixtureNativePeer{owner: body.IdempotencyKey, seen: make(map[string]struct{})}
	var delivery [16]byte
	if _, err := rand.Read(delivery[:]); err != nil {
		return controlv1.NativePeerPair{}, err
	}
	if _, err := rand.Read(p.key[:]); err != nil {
		return controlv1.NativePeerPair{}, err
	}
	p.pair = controlv1.NativePeerPair{PairId: id, DeliveryId: base64.RawURLEncoding.EncodeToString(delivery[:]), Key: base64.RawURLEncoding.EncodeToString(p.key[:]), DeliveryGeneration: 1,
		ServiceId: service, ServiceRunId: body.ServiceRunId, RunNumber: body.RunNumber, PublisherIdentityId: body.PublisherIdentityId, Subject: body.Subject, Relays: body.ExpectedRelays, ObservedAt: time.Now(), ExpiresAt: f.expires}
	for slot := range p.paths {
		p.paths[slot] = make(chan peer.Carrier, 1)
	}
	f.peers[id] = p
	ready := make(chan error, 1)
	f.workers.Go(func() { f.serveNativePeer(p, ready) })
	select {
	case err := <-ready:
		if err == nil {
			p.pair.PublisherPreparedUntil = new(p.pair.ExpiresAt)
		}
		return p.pair, err
	case <-ctx.Done():
		return controlv1.NativePeerPair{}, context.Cause(ctx)
	}
}

func (f *connectorFixture) serveNativePeer(p *fixtureNativePeer, ready chan<- error) {
	// the fixture accepts each carrier once. there is no reconnect or
	// replacement of a physical carrier within an existing inner session.
	ready <- nil
	var paths [2]peer.Carrier
	for slot, incoming := range p.paths {
		select {
		case paths[slot] = <-incoming:
			defer paths[slot].Close()
		case <-f.ctx.Done():
			return
		}
	}
	packets, err := peer.New(f.ctx, peer.Config{Key: p.key, Role: 1, Paths: paths})
	if err != nil {
		return
	}
	defer packets.Close()
	transport := &quic.Transport{Conn: packets}
	defer transport.Close()
	listener, err := transport.Listen(&tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{muxsession.ALPN}, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		if f.wrongInnerCertificate.Load() {
			return &f.badCertificate, nil
		}
		return &f.certificate, nil
	}}, &quic.Config{InitialPacketSize: tunnelv1.MaxPeerPacketBytes, DisablePathMTUDiscovery: true, MaxIncomingStreams: 64})
	if err != nil {
		return
	}
	defer listener.Close()
	connection, err := listener.Accept(f.ctx)
	if err != nil {
		return
	}
	session, err := muxsession.AdoptQUIC(connection)
	if err != nil {
		return
	}
	defer session.Close()
	f.mu.Lock()
	p.session = session
	f.mu.Unlock()
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		stream, err := session.AcceptStream(f.ctx)
		if err != nil {
			return
		}
		workers.Go(func() { defer stream.Close(); f.visitor(f.ctx, stream, p) })
	}
}
