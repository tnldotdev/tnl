package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type connectorClaimFunc func(context.Context, relayv1.RelayLease, netip.Addr, tunnelv1.ConnectorPairLegProof, []byte) (relayv1.ConnectorPeerPairLegClaim, error)

func (f connectorClaimFunc) ClaimConnectorPeerPairLegFromAcceptedSocket(ctx context.Context, lease relayv1.RelayLease, source netip.Addr, proof tunnelv1.ConnectorPairLegProof, signature []byte) (relayv1.ConnectorPeerPairLegClaim, error) {
	return f(ctx, lease, source, proof, signature)
}

type connectorObservedSession struct {
	*forwardingTestSession
	*connectorSourcePeer
}

type connectorBindingFixture struct {
	acceptor           *ConnectorAcceptor
	publisher          *connectorPacketSession
	publisherTransport *forwardingTestSession
	connection         *serviceConnection
	proof              tunnelv1.ConnectorPairLegProof
	id                 [16]byte
	nonce              uint64
	duration           time.Duration
}

func newConnectorBindingFixture(t *testing.T) *connectorBindingFixture {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	lease := relayv1.RelayLease{RelayServiceId: "relay-a", RelayId: "process-a", RelayRunId: "relay-run", RelayLeaseRevision: 1, LeaseExpiresAt: time.Now().Add(time.Minute), PeerSigningPublicKey: &public}
	proof := tunnelv1.ConnectorPairLegProof{PairID: "cpp_1234567890123456789012", DeliveryGeneration: 1, ServiceID: "svc_1234567890123456789012", ServiceRunID: "srun_1234567890123456789012", RunNumber: 1, PublisherIdentityID: "pub_1234567890123456789012", ConnectionSlot: 0, PublisherConnectionID: "pc_1234567890123456789012", AssignmentRevision: 1, RelayServiceID: lease.RelayServiceId, RelayID: lease.RelayId, RelayRunID: lease.RelayRunId, RelayLeaseRevision: 1, RequestedAt: time.Now(), Nonce: make([]byte, 32), Signature: make([]byte, 64)}
	ref := tunnelv1.ServicePublisherConnectionRef{ServiceID: proof.ServiceID, ServiceRunID: proof.ServiceRunID, RunNumber: 1, PublisherConnectionID: proof.PublisherConnectionID, ConnectionSlot: 0, ConnectionAssignmentRevision: 1, RelayServiceID: lease.RelayServiceId}
	outer := newForwardingTestSession()
	packets, err := newConnectorPacketSession(t.Context(), outer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { packets.Close(); _ = outer.Close() })
	connection := &serviceConnection{ref: ref, lease: lease, paths: newStreamLifetime(nil), packets: packets}
	registry := NewServiceRegistry()
	registry.connections[ref.PublisherConnectionID] = connection
	f := &connectorBindingFixture{acceptor: &ConnectorAcceptor{CurrentLease: func() relayv1.RelayLease { return lease }, SigningKey: key, Publishers: registry}, publisher: packets, publisherTransport: outer, connection: connection, proof: proof, id: [16]byte{1}}
	f.acceptor.Claim = connectorClaimFunc(func(_ context.Context, _ relayv1.RelayLease, source netip.Addr, proof tunnelv1.ConnectorPairLegProof, signature []byte) (relayv1.ConnectorPeerPairLegClaim, error) {
		message, err := proof.RelayClaimMessage(source)
		if err != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), message, signature) {
			t.Error("relay did not sign its canonical socket source", err)
		}
		state, duration := relayv1.ConnectorPeerLegBindingActive, time.Minute
		if proof.DeliveryGeneration > 1 {
			state, duration = relayv1.ConnectorPeerLegBindingPrepared, 10*time.Second
		}
		if f.duration != 0 {
			duration = f.duration
		}
		now := time.Now()
		return relayv1.ConnectorPeerPairLegClaim{PairId: proof.PairID, DeliveryId: base64.RawURLEncoding.EncodeToString(f.id[:]), DeliveryGeneration: proof.DeliveryGeneration, BindingState: state, ConnectionSlot: proof.ConnectionSlot, SourceIp: source.String(), Key: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(proof.DeliveryGeneration)}, 32)), ObservedAt: now, ExpiresAt: now.Add(duration)}, nil
	})
	return f
}

func (f *connectorBindingFixture) candidate(t *testing.T, generation int64, ip string) (*connectorDelivery, *connectorObservedSession) {
	t.Helper()
	f.nonce++
	proof := f.proof
	proof.DeliveryGeneration = generation
	proof.RequestedAt = f.proof.RequestedAt.Add(time.Duration(f.nonce) * time.Microsecond)
	proof.Nonce = make([]byte, 32)
	binary.BigEndian.PutUint64(proof.Nonce[24:], f.nonce)
	accepted := &connectorSourcePeer{}
	accepted.move(ip)
	outer := &connectorObservedSession{forwardingTestSession: newForwardingTestSession(), connectorSourcePeer: accepted}
	t.Cleanup(func() { _ = outer.Close() })
	claim, err := f.acceptor.claim(t.Context(), outer, proof)
	if err != nil {
		t.Fatal(err)
	}
	d := newConnectorDelivery(t.Context(), f.publisher.Done(), proof, claim)
	raw := newReconnectCarrier()
	d.carrier = newConnectorBindingCarrier(raw, claim.source, d.admit, d.cancel)
	t.Cleanup(func() { d.close(); _ = raw.Close() })
	return d, outer
}

func (f *connectorBindingFixture) activate(t *testing.T, d *connectorDelivery, operation tunnelv1.ConnectorHandoffID) (*connectorBridge, error) {
	t.Helper()
	hello, err := tunnelv1.ParseConnectorHelloNonce(d.proof.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	activation := tunnelv1.InitialConnectorActivation(hello)
	if operation != (tunnelv1.ConnectorHandoffID{}) {
		activation, err = tunnelv1.InitialConnectorBindingActivation(hello, operation)
		if err != nil {
			t.Fatal(err)
		}
	}
	return f.publisher.selectBridge(t.Context(), f.acceptor, d, f.id, activation.Binding())
}

// isolate renewal/retirement ordering from the bridge's forwarding workers.
func isolatedConnectorBridge(t *testing.T, d *connectorDelivery, ctx context.Context) *connectorBridge {
	t.Helper()
	slot := peer.NewCarrierSlot()
	t.Cleanup(func() { _ = slot.Close() })
	b := &connectorBridge{ctx: ctx, active: d, connector: slot, until: d.claim.receipt.ExpiresAt, state: d.claim.receipt.BindingState}
	d.stopPreparation()
	d.bridge.Store(b)
	return b
}

func TestConnectorBindingReplacesGenerationAfterJoiningOldBridge(t *testing.T) {
	f := newConnectorBindingFixture(t)
	first, _ := f.candidate(t, 1, "192.0.2.1:12345")
	old, err := f.activate(t, first, tunnelv1.ConnectorHandoffID{})
	if err != nil {
		t.Fatal(err)
	}
	second, _ := f.candidate(t, 2, "192.0.2.2:12345")
	next, err := f.activate(t, second, tunnelv1.ConnectorHandoffID{9})
	if err != nil {
		t.Fatal("fresh binding reused old handoff or registration", err)
	}
	select {
	case <-old.done:
	default:
		t.Fatal("successor installed before old registration joined")
	}
	if old == next || old.publisher == next.publisher || old.claim.key == next.claim.key || first.ctx.Err() == nil || next.handoff.operation.Revision() != 0 || second.admit(tunnelv1.PeerPacket{Kind: tunnelv1.PeerData}) {
		t.Fatal("new generation inherited a carrier, key, active flag, or handoff history")
	}
	f.publisher.removeBridge(f.id, old)
	f.publisher.mu.Lock()
	current := f.publisher.bridges[f.id]
	f.publisher.mu.Unlock()
	if current != next || next.ctx.Err() != nil {
		t.Fatal("old cleanup removed the fresh-generation owner")
	}
	late, _ := f.candidate(t, 1, "192.0.2.1:12345")
	if _, err := f.activate(t, late, tunnelv1.ConnectorHandoffID{}); err == nil {
		t.Fatal("older generation restored its delivery")
	}
}

func TestConnectorBindingInitialOperationSurvivesLostActivationReply(t *testing.T) {
	f := newConnectorBindingFixture(t)
	initial := tunnelv1.ConnectorHandoffID{9}
	lostHello, _ := f.candidate(t, 2, "192.0.2.2:12345")
	lostHello.cancel()
	first, _ := f.candidate(t, 2, "192.0.2.2:12345")
	b, err := f.activate(t, first, initial)
	if err != nil {
		t.Fatal(err)
	}
	until, publisher := b.until, b.publisher
	first.cancel()
	b.detach(first)
	fresh, _ := f.candidate(t, 2, "192.0.2.2:12345")
	retried, err := f.activate(t, fresh, initial)
	if err != nil || retried != b || b.publisher != publisher || b.until != until || fresh.bridge.Load() != b || b.handoff.operation.Revision() != 0 || b.handoff.selected != initial {
		t.Fatal("lost initial reply changed binding, authority or operation", err)
	}
	advanced, _ := f.candidate(t, 2, "192.0.2.2:12345")
	handoff, err := tunnelv1.NewConnectorHandoff(initial, tunnelv1.ConnectorHandoffID{10}, 1)
	if err != nil {
		t.Fatal(err)
	}
	hello, _ := tunnelv1.ParseConnectorHelloNonce(advanced.proof.Nonce)
	if _, err := f.publisher.selectBridge(t.Context(), f.acceptor, advanced, f.id, tunnelv1.InitialConnectorActivation(hello).Replacing(handoff).Binding()); err != nil {
		t.Fatal("first numbered handoff did not follow stable initial identity", err)
	}
	stale, _ := f.candidate(t, 2, "192.0.2.2:12345")
	if _, err := f.activate(t, stale, initial); err == nil || b.active != advanced || b.publisher != publisher {
		t.Fatal("late initial operation reset a newer handoff", err)
	}
}

func TestConnectorBindingMigrationRetiresPacketsButReportsStaleOnControlRenewal(t *testing.T) {
	f := newConnectorBindingFixture(t)
	d, outer := f.candidate(t, 1, "192.0.2.1:12345")
	ready := d.carrier
	outer.move("192.0.2.2:12345")
	if err := ready.Send(t.Context(), nil); !errors.Is(err, errConnectorSocketSourceChanged) {
		t.Fatal("migration was not checked before the ready gate", err)
	}
	if err := ready.Close(); err != nil || d.ctx.Err() != nil {
		t.Fatal("physical retirement erased the bounded control result", err)
	}
	var called atomic.Bool
	f.acceptor.Claim = connectorClaimFunc(func(context.Context, relayv1.RelayLease, netip.Addr, tunnelv1.ConnectorPairLegProof, []byte) (relayv1.ConnectorPeerPairLegClaim, error) {
		called.Store(true)
		return relayv1.ConnectorPeerPairLegClaim{}, errors.New("must not claim a moved socket")
	})
	_, err := d.renew(t.Context(), f.acceptor, outer, d.proof)
	var stale *tunnel.ProtocolError
	if called.Load() || !errors.As(err, &stale) || stale.Code != tunnelv1.StaleNetworkBinding {
		t.Fatal("migration claimed a new source or became generic denial", err)
	}
}

var _ peer.Carrier = (*connectorBindingCarrier)(nil)

func TestConnectorBindingPreparedRenewalCannotExtendUntilExplicitlyActive(t *testing.T) {
	f := newConnectorBindingFixture(t)
	f.duration = 5 * time.Second
	d, outer := f.candidate(t, 2, "192.0.2.2:12345")
	bound := d.claim.receipt.ExpiresAt
	initial := tunnelv1.ConnectorHandoffID{9}
	b, err := f.activate(t, d, initial)
	if err != nil {
		t.Fatal(err)
	}
	proof := d.proof
	proof.Nonce = bytes.Repeat([]byte{8}, 32)
	proof.RequestedAt = proof.RequestedAt.Add(time.Microsecond)
	receipt, err := d.renew(t.Context(), f.acceptor, outer, proof)
	if err != nil || b.until != bound || receipt.ExpiresAt != bound || d.admit(tunnelv1.PeerPacket{Kind: tunnelv1.PeerData}) {
		t.Fatal("pending repeat extended authority or admitted application data", err)
	}
	prior := f.acceptor.Claim
	f.acceptor.Claim = connectorClaimFunc(func(ctx context.Context, lease relayv1.RelayLease, source netip.Addr, proof tunnelv1.ConnectorPairLegProof, signature []byte) (relayv1.ConnectorPeerPairLegClaim, error) {
		claim, err := prior.ClaimConnectorPeerPairLegFromAcceptedSocket(ctx, lease, source, proof, signature)
		claim.BindingState = relayv1.ConnectorPeerLegBindingActive
		claim.ExpiresAt = claim.ObservedAt.Add(time.Minute)
		return claim, err
	})
	receipt, err = d.renew(t.Context(), f.acceptor, outer, proof)
	if err != nil || !b.until.After(bound) || receipt.ExpiresAt != b.until || receipt.BindingState != tunnelv1.ConnectorPeerLegBindingActive || !d.admit(tunnelv1.PeerPacket{Kind: tunnelv1.PeerData}) {
		t.Fatal("checked activation did not promote the exact existing carrier", err)
	}
	activeUntil := b.until
	f.acceptor.Claim = prior
	if _, err := d.renew(t.Context(), f.acceptor, outer, proof); err == nil || !d.admit(tunnelv1.PeerPacket{Kind: tunnelv1.PeerData}) || b.until != activeUntil {
		t.Fatal("old prepared claim restored an earlier state or deadline", err)
	}
}

func TestConnectorBindingActiveConfirmationRequiresExactClaimAndLiveness(t *testing.T) {
	for _, boundary := range []string{"key", "source", "generation", "expired", "canceled", "migration", "long preparation", "missing state"} {
		t.Run(boundary, func(t *testing.T) {
			f := newConnectorBindingFixture(t)
			d, outer := f.candidate(t, 2, "192.0.2.2:12345")
			b, err := f.activate(t, d, tunnelv1.ConnectorHandoffID{9})
			if err != nil {
				t.Fatal(err)
			}
			until := b.until
			prior := f.acceptor.Claim
			f.acceptor.Claim = connectorClaimFunc(func(ctx context.Context, lease relayv1.RelayLease, source netip.Addr, proof tunnelv1.ConnectorPairLegProof, signature []byte) (relayv1.ConnectorPeerPairLegClaim, error) {
				claim, err := prior.ClaimConnectorPeerPairLegFromAcceptedSocket(ctx, lease, source, proof, signature)
				claim.BindingState = relayv1.ConnectorPeerLegBindingActive
				switch boundary {
				case "key":
					claim.Key = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
				case "source":
					claim.SourceIp = "192.0.2.3"
				case "generation":
					claim.DeliveryGeneration++
				case "expired":
					claim.ExpiresAt = claim.ObservedAt
				case "canceled":
					d.cancel()
				case "migration":
					outer.move("192.0.2.3:12345")
				case "long preparation":
					claim.BindingState = relayv1.ConnectorPeerLegBindingPrepared
					claim.ExpiresAt = claim.ObservedAt.Add(11 * time.Second)
				case "missing state":
					claim.BindingState = ""
				}
				return claim, err
			})
			if _, err := d.renew(t.Context(), f.acceptor, outer, d.proof); err == nil || d.admit(tunnelv1.PeerPacket{Kind: tunnelv1.PeerData}) || b.until != until {
				t.Fatal("invalid confirmation enabled data or changed authority", err)
			}
		})
	}
}

func TestConnectorBindingPublisherAdmissionFollowsCurrentCandidate(t *testing.T) {
	f := newConnectorBindingFixture(t)
	first, _ := f.candidate(t, 2, "192.0.2.2:12345")
	initial := tunnelv1.ConnectorHandoffID{9}
	b, err := f.activate(t, first, initial)
	if err != nil {
		t.Fatal(err)
	}
	data := tunnelv1.PeerPacket{Kind: tunnelv1.PeerData}
	probe := tunnelv1.PeerPacket{Kind: tunnelv1.PeerProbe}
	if b.admit(data) || !b.admit(probe) {
		t.Fatal("prepared publisher registration admitted data or blocked probes")
	}
	b.mu.Lock()
	b.state = tunnelv1.ConnectorPeerLegBindingActive
	b.mu.Unlock()
	if !b.admit(data) {
		t.Fatal("active publisher registration remained fenced")
	}
	second, _ := f.candidate(t, 2, "192.0.2.2:54321")
	handoff, err := tunnelv1.NewConnectorHandoff(initial, tunnelv1.ConnectorHandoffID{10}, 1)
	if err != nil {
		t.Fatal(err)
	}
	hello, _ := tunnelv1.ParseConnectorHelloNonce(second.proof.Nonce)
	if _, err := f.publisher.selectBridge(t.Context(), f.acceptor, second, f.id, tunnelv1.InitialConnectorActivation(hello).Replacing(handoff).Binding()); err != nil {
		t.Fatal(err)
	}
	if b.admit(data) || !b.admit(probe) {
		t.Fatal("replacement inherited its predecessor's active admission")
	}
	b.mu.Lock()
	b.state = tunnelv1.ConnectorPeerLegBindingActive
	b.mu.Unlock()
	if !b.admit(data) {
		t.Fatal("replacement activation did not update the retained registration")
	}
	second.cancel()
	b.detach(second)
	if b.admit(data) || b.admit(probe) {
		t.Fatal("detached registration retained packet admission")
	}
}
