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
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// the fixture supplies authority replies and connector packet acceptance. the
// production connector still owns pair preparation, carrier races, inner QUIC,
// openings, TLS, renewal and cleanup. publisher policy is covered by its owner
// and the real daemon consumer tests, not reimplemented here.
type fixtureConnectorPeer struct {
	owner           string
	pair            controlv1.ConnectorPeerPair
	key             [32]byte
	paths           [2]*peer.CarrierSlot
	nonces          [2][]byte
	handoffs        [2]tunnelv1.ConnectorHandoff
	seen            map[string]struct{}
	session         muxsession.Session
	updates         chan tunnelv1.ConnectorPermissionUpdate
	control         muxsession.Stream
	renewalGate     [2]*fixtureTLSGate
	permissionReply func(tunnelv1.ConnectorPermissionUpdate, *tunnel.ConnectorPermissionResponder)
}

type fixtureTLSGate struct {
	entered, release chan struct{}
	once             sync.Once
}

func fixtureDatagramConfig() *quic.Config { return &quic.Config{EnableDatagrams: true} }

func (p *fixtureConnectorPeer) receipt(slot int) tunnelv1.ConnectorPairLegAccepted {
	return tunnelv1.ConnectorPairLegAccepted{PairID: p.pair.PairId, DeliveryID: p.pair.DeliveryId, DeliveryGeneration: p.pair.DeliveryGeneration,
		ConnectionSlot: slot, SourceIP: "127.0.0.1", ObservedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
}

func (f *connectorFixture) PrepareConnectorPeerPair(ctx context.Context, service string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
	message, err := controlv1.ConnectorPeerPairProofMessage(service, body)
	signature, decodeErr := base64.RawURLEncoding.DecodeString(body.Signature)
	if err != nil || decodeErr != nil || !ed25519.Verify(f.device.PublicKey, message, signature) || !visitorsubject.Equal(body.Subject, f.device.Subject) {
		return controlv1.ConnectorPeerPair{}, ErrServiceConnection
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if ctx.Err() != nil || f.ctx.Err() != nil {
		return controlv1.ConnectorPeerPair{}, context.Canceled
	}
	for _, p := range f.peers {
		if p.owner == body.IdempotencyKey {
			result := p.pair
			result.ObservedAt, result.ExpiresAt = time.Now(), f.expires
			return result, nil
		}
	}
	id, err := opaqueid.New("cpp_")
	if err != nil {
		return controlv1.ConnectorPeerPair{}, err
	}
	p := &fixtureConnectorPeer{owner: body.IdempotencyKey, seen: make(map[string]struct{})}
	var delivery [16]byte
	if _, err := rand.Read(delivery[:]); err != nil {
		return controlv1.ConnectorPeerPair{}, err
	}
	if _, err := rand.Read(p.key[:]); err != nil {
		return controlv1.ConnectorPeerPair{}, err
	}
	p.pair = controlv1.ConnectorPeerPair{PairId: id, DeliveryId: base64.RawURLEncoding.EncodeToString(delivery[:]), Key: base64.RawURLEncoding.EncodeToString(p.key[:]), DeliveryGeneration: 1,
		ServiceId: service, ServiceRunId: body.ServiceRunId, RunNumber: body.RunNumber, PublisherIdentityId: body.PublisherIdentityId, Subject: body.Subject, Relays: body.ExpectedRelays, ObservedAt: time.Now(), ExpiresAt: f.expires}
	for slot := range p.paths {
		p.paths[slot] = peer.NewCarrierSlot()
	}
	f.peers[id] = p
	ready := make(chan error, 1)
	f.workers.Go(func() { f.serveConnectorPeer(p, ready) })
	select {
	case err := <-ready:
		if err == nil {
			p.pair.PublisherPreparedUntil = new(p.pair.ExpiresAt)
		}
		return p.pair, err
	case <-ctx.Done():
		return controlv1.ConnectorPeerPair{}, context.Cause(ctx)
	}
}

func (f *connectorFixture) RebindConnectorPeerPair(context.Context, string, string, controlv1.ConnectorPeerPairRebindRequest) (controlv1.ConnectorPeerPairRebindState, error) {
	return controlv1.ConnectorPeerPairRebindState{}, ErrServiceConnection
}

func (f *connectorFixture) RenewConnectorPeerPair(ctx context.Context, service string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
	pair, err := f.PrepareConnectorPeerPair(ctx, service, body)
	if err != nil {
		return controlv1.ConnectorPeerPairRenewal{}, err
	}
	permission, err := f.VisitorPermission(ctx, service)
	f.mu.Lock()
	run := f.run
	f.mu.Unlock()
	if permission.ExpiresAt.After(pair.ExpiresAt) {
		permission.ExpiresAt = pair.ExpiresAt
	}
	return controlv1.ConnectorPeerPairRenewal{Pair: pair, RunValidUntil: run.ValidUntil, VisitorPermission: permission,
		Protocol: controlv1.ServiceProtocol(run.Protocol), TrustRevision: run.TrustRevision, Endpoint: *run.Endpoint}, err
}

func (f *connectorFixture) serveConnectorPeer(p *fixtureConnectorPeer, ready chan<- error) {
	ready <- nil
	paths := [2]peer.Carrier{p.paths[0], p.paths[1]}
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
	}}, tunnel.ConnectorQUICConfig())
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
	setup, stop := context.WithTimeout(f.ctx, 3*time.Second)
	permissions, err := tunnel.AcceptConnectorPermissionControl(setup, session)
	stop()
	if err != nil {
		return
	}
	f.mu.Lock()
	p.control = permissions
	f.mu.Unlock()
	control, cancelControl := context.WithCancel(f.ctx)
	defer cancelControl()
	workers.Go(func() {
		_ = tunnel.ServeConnectorPermissionControl(control, permissions, func(update tunnelv1.ConnectorPermissionUpdate, responder *tunnel.ConnectorPermissionResponder) {
			f.mu.Lock()
			updates := p.updates
			reply := p.permissionReply
			f.mu.Unlock()
			if updates != nil {
				select {
				case updates <- update:
				case <-control.Done():
				}
			}
			if reply != nil {
				workers.Go(func() { reply(update, responder) })
			} else {
				_ = responder.Respond(update, true)
			}
		}, func() { _ = session.Close() })
	})
	for {
		stream, err := session.AcceptStream(f.ctx)
		if err != nil {
			// inner close packets are queued on the borrowed carriers. keep the
			// fixture's packet transport alive until its owning context ends,
			// rather than discarding that close during session teardown.
			<-f.ctx.Done()
			return
		}
		workers.Go(func() { defer stream.Close(); f.visitor(f.ctx, stream, p) })
	}
}
