package stream

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/internal/testutil/connectorfixture"
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
	sessionKey      [32]byte
	paths           [2]*peer.CarrierSlot
	nonces          [2][]byte
	handoffs        [2]tunnelv1.ConnectorHandoff
	seen            map[string]*connectorfixture.JoinedVisitor
	controlOwner    *connectorfixture.JoinedControl
	retirement      *connectorfixture.Retirement
	retired         bool
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
		BindingState: tunnelv1.ConnectorPeerLegBindingActive, ConnectionSlot: slot, SourceIP: "127.0.0.1", ObservedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
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
			if p.retired {
				return controlv1.ConnectorPeerPair{}, ErrServiceConnection
			}
			result := p.pair
			result.ObservedAt, result.ExpiresAt = time.Now(), f.expires
			return result, nil
		}
	}
	id, err := opaqueid.New("cpp_")
	if err != nil {
		return controlv1.ConnectorPeerPair{}, err
	}
	p := &fixtureConnectorPeer{owner: body.IdempotencyKey, seen: make(map[string]*connectorfixture.JoinedVisitor)}
	var delivery [16]byte
	if _, err := rand.Read(delivery[:]); err != nil {
		return controlv1.ConnectorPeerPair{}, err
	}
	if _, err := rand.Read(p.key[:]); err != nil {
		return controlv1.ConnectorPeerPair{}, err
	}
	if _, err := rand.Read(p.sessionKey[:]); err != nil {
		return controlv1.ConnectorPeerPair{}, err
	}
	p.pair = controlv1.ConnectorPeerPair{PairId: id, DeliveryId: base64.RawURLEncoding.EncodeToString(delivery[:]), Key: base64.RawURLEncoding.EncodeToString(p.key[:]), DeliveryGeneration: 17,
		SessionKey: base64.RawURLEncoding.EncodeToString(p.sessionKey[:]), BindingState: controlv1.ConnectorPeerPairBindingActive, TrustRevision: f.run.TrustRevision,
		ServiceId: service, ServiceRunId: body.ServiceRunId, RunNumber: body.RunNumber, PublisherIdentityId: body.PublisherIdentityId, Subject: body.Subject, Relays: body.ExpectedRelays, ObservedAt: time.Now(), ExpiresAt: f.expires}
	p.retirement = connectorfixture.NewRetirement(p.pair, p.owner, f.device.PublicKey, p.sessionKey)
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

func (f *connectorFixture) RetireConnectorPeerPair(ctx context.Context, service, pair string, body controlv1.ConnectorPeerPairRetireRequest) (controlv1.ConnectorPeerPairRetirement, error) {
	f.mu.Lock()
	peer := f.peers[pair]
	f.mu.Unlock()
	if peer == nil {
		return controlv1.ConnectorPeerPairRetirement{}, ErrServiceConnection
	}
	receipt, err := peer.retirement.Retire(ctx, service, pair, body)
	if err != nil {
		return receipt, err
	}
	f.mu.Lock()
	peer.retired = true
	owner, session := peer.controlOwner, peer.session
	f.mu.Unlock()
	return receipt, f.retirePeerControl(session, owner)
}

// retirement is a negative authority decision, not a control-stream reset.
// keep the packet owner alive and close the session before canceling its decoder.
func (f *connectorFixture) retirePeerControl(session muxsession.Session, owner *connectorfixture.JoinedControl) error {
	var err error
	if session != nil {
		err = session.Close()
	}
	if owner != nil {
		owner.Retire()
	}
	if err != nil {
		f.mu.Lock()
		f.peerCloseErr = errors.Join(f.peerCloseErr, err)
		f.mu.Unlock()
	}
	return err
}

type fixtureRetirementSession struct {
	muxsession.Session
	close func() error
}

func (s fixtureRetirementSession) Close() error { return s.close() }

func TestConnectorFixtureRetirementClosesSessionBeforeControlCancellation(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "independent close failure"}[mixed], func(t *testing.T) {
			f := new(connectorFixture)
			control := connectorfixture.NewJoinedControl(t.Context(), connectorTestControlScope(), nil)
			defer control.Retire()
			var cause error
			if mixed {
				cause = errors.Join(context.Canceled, errors.New("fixture physical close failed"))
			}
			closed := false
			session := fixtureRetirementSession{close: func() error {
				if control.Context.Err() != nil {
					t.Fatal("fixture reset live control before closing its session")
				}
				closed = true
				return cause
			}}
			err := f.retirePeerControl(session, control)
			if !closed || control.Context.Err() != context.Canceled || !errors.Is(err, cause) {
				t.Fatal("fixture did not finish session closure before control cancellation", err)
			}
			f.mu.Lock()
			retained := f.peerCloseErr
			f.mu.Unlock()
			if !errors.Is(retained, cause) {
				t.Fatal("fixture cleanup lost an independent session close failure", retained)
			}
		})
	}
}

func (f *connectorFixture) RebindConnectorPeerPair(ctx context.Context, service, pairID string, body controlv1.ConnectorPeerPairRebindRequest) (controlv1.ConnectorPeerPairRebindState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.peers[pairID]
	message, err := controlv1.ConnectorPeerPairRebindProofMessage(service, pairID, body)
	signature, decodeErr := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
	if p == nil || ctx.Err() != nil || err != nil || decodeErr != nil || !ed25519.Verify(f.device.PublicKey, message, signature) || body.Phase != controlv1.ConnectorPeerPairInspect {
		return controlv1.ConnectorPeerPairRebindState{}, ErrServiceConnection
	}
	pair := p.pair
	pair.ObservedAt, pair.ExpiresAt, pair.SourceIp = time.Now(), f.expires, new("127.0.0.1")
	return controlv1.ConnectorPeerPairRebindState{Active: &pair, HighWaterGeneration: pair.DeliveryGeneration, ReadyRelays: pair.Relays}, nil
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
	packets, err := peer.New(f.ctx, peer.Config{Key: p.sessionKey, Role: 1, Binding: peer.BindingRevision{PairID: p.pair.PairId, Generation: p.pair.DeliveryGeneration}, Paths: paths})
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
	scope := tunnelv1.ConnectorControlScope{ServiceID: p.pair.ServiceId, ServiceRunID: p.pair.ServiceRunId, RunNumber: uint64(p.pair.RunNumber),
		PublisherIdentityID: p.pair.PublisherIdentityId, PairID: p.pair.PairId}
	control := connectorfixture.NewJoinedControl(f.ctx, scope, func(key tunnelv1.ConnectorVisitorTerminalKey) *connectorfixture.JoinedVisitor {
		f.mu.Lock()
		defer f.mu.Unlock()
		return p.seen[key.VisitorConnectionID]
	})
	control.Permission = func(update tunnelv1.ConnectorPermissionUpdate, responder *tunnel.ConnectorPermissionResponder) {
		f.mu.Lock()
		updates, reply := p.updates, p.permissionReply
		f.mu.Unlock()
		if updates != nil {
			select {
			case updates <- update:
			case <-control.Context.Done():
			}
		}
		if reply != nil {
			reply(update, responder)
		} else {
			ack, stop := context.WithTimeout(control.Context, 2*time.Second)
			defer stop()
			_ = responder.Respond(ack, update, true)
		}
	}
	f.mu.Lock()
	p.controlOwner = control
	retired := p.retired
	f.mu.Unlock()
	if retired {
		_ = f.retirePeerControl(session, control)
	}
	defer control.Retire()
	var permissionGate tunnel.ConnectorPermissionGate
	workers.Go(func() {
		_ = control.Serve(permissions, &permissionGate)
	})
	for {
		stream, err := session.AcceptStream(control.Context)
		if err != nil {
			// inner close packets are queued on the borrowed carriers. keep the
			// fixture's packet transport alive until its owning context ends,
			// rather than discarding that close during session teardown.
			<-f.ctx.Done()
			return
		}
		workers.Go(func() { _ = f.visitor(control.Context, stream, p) })
	}
}
