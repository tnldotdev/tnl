package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// ConnectorAcceptor attests the directly accepted socket source and owns
// bounded native relay candidates. no opening supplies source
// authority. activation alone selects a candidate for packet delivery.
type ConnectorAcceptor struct {
	CurrentLease     func() relayv1.RelayLease
	SigningKey       ed25519.PrivateKey
	Claim            ConnectorPeerLegClaimClient
	Publishers       *ServiceRegistry
	PublicPublishers *Registry
	mu               sync.Mutex
	sessions         int
	runs             map[connectorRun]int
	legs             map[connectorLegID]int
}

type connectorLegID struct {
	pair       string
	generation int64
	slot       int
}

type connectorRun struct {
	serviceRunID, publishRunID string
}

const maxConnectorSessions = 64
const maxConnectorSessionsPerRun = 8

func (a *ConnectorAcceptor) reserve(proof tunnelv1.ConnectorPairLegProof) (func(), error) {
	if a == nil || a.CurrentLease == nil || a.Claim == nil ||
		proof.PublicURLID == "" && a.Publishers == nil || proof.PublicURLID != "" && a.PublicPublishers == nil ||
		len(a.SigningKey) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(a.SigningKey.Seed()), a.SigningKey) {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	}
	id := connectorLegID{proof.PairID, proof.DeliveryGeneration, proof.ConnectionSlot}
	run := connectorRun{serviceRunID: proof.ServiceRunID, publishRunID: proof.PublishRunID}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sessions >= maxConnectorSessions || a.runs[run] >= maxConnectorSessionsPerRun || a.legs[id] >= 2 {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
	}
	if a.legs == nil {
		a.legs = make(map[connectorLegID]int)
	}
	if a.runs == nil {
		a.runs = make(map[connectorRun]int)
	}
	a.sessions++
	a.runs[run]++
	a.legs[id]++
	return sync.OnceFunc(func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.sessions--
		a.runs[run]--
		if a.runs[run] == 0 {
			delete(a.runs, run)
		}
		a.legs[id]--
		if a.legs[id] == 0 {
			delete(a.legs, id)
		}
	}), nil
}

type connectorClaim struct {
	receipt tunnelv1.ConnectorPairLegAccepted
	ref     tunnelv1.ServicePublisherConnectionRef
	public  tunnelv1.PublisherConnectionRef
	key     [32]byte
	source  *connectorSocketSource
}

func (connectorClaim) String() string   { return "connector claim" }
func (connectorClaim) GoString() string { return "connector claim" }

func (c connectorClaim) samePublisher(other connectorClaim) bool {
	return c.ref == other.ref && c.public == other.public
}

// select only the exact publication family. packet ownership is shared, not
// the registries' publication references or their current claim authority.
func (a *ConnectorAcceptor) publisherPackets(claim connectorClaim, lease relayv1.RelayLease) (*connectorPacketSession, bool) {
	if claim.public != (tunnelv1.PublisherConnectionRef{}) {
		if claim.ref != (tunnelv1.ServicePublisherConnectionRef{}) || a.PublicPublishers == nil {
			return nil, false
		}
		connection, current := a.PublicPublishers.connectorCandidate(claim.public, lease)
		if !current {
			return nil, false
		}
		return connection.packets, true
	}
	if a.Publishers == nil {
		return nil, false
	}
	connection, current := a.Publishers.connectorCandidate(claim.ref, lease)
	if !current {
		return nil, false
	}
	return connection.packets, true
}

func (a *ConnectorAcceptor) currentLease(proof tunnelv1.ConnectorPairLegProof) (relayv1.RelayLease, bool) {
	lease := a.CurrentLease()
	valid := lease.RelayServiceId == proof.RelayServiceID && lease.RelayId == proof.RelayID && lease.RelayRunId == proof.RelayRunID && lease.RelayLeaseRevision > 0 && uint64(lease.RelayLeaseRevision) == proof.RelayLeaseRevision &&
		!lease.Draining && lease.LeaseExpiresAt.After(time.Now()) && lease.PeerSigningPublicKey != nil && *lease.PeerSigningPublicKey == base64.RawURLEncoding.EncodeToString(a.SigningKey.Public().(ed25519.PublicKey))
	return lease, valid
}

func (a *ConnectorAcceptor) claim(ctx context.Context, outer muxsession.Session, proof tunnelv1.ConnectorPairLegProof) (connectorClaim, error) {
	claim, err := a.claimFromControl(ctx, outer, proof)
	if err = errors.Join(err, context.Cause(ctx)); err != nil {
		return connectorClaim{}, connectorClaimError(err)
	}
	return claim, nil
}

// validate the control reply independently of cancellation. claim checks its
// caller before returning authority; renew first checks the retained binding,
// so concurrent cancellation cannot hide a changed key or an expired deadline.
func (a *ConnectorAcceptor) claimFromControl(ctx context.Context, outer muxsession.Session, proof tunnelv1.ConnectorPairLegProof) (connectorClaim, error) {
	denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	accepted, ok := outer.(muxsession.AcceptedPeer)
	if !ok || proof.Validate() != nil {
		return connectorClaim{}, denied
	}
	observed, err := newConnectorSocketSource(accepted)
	if err != nil {
		return connectorClaim{}, denied
	}
	source := observed.ip
	lease, valid := a.currentLease(proof)
	if !valid {
		// a restarted relay can receive a proof for its predecessor before the
		// connector observes replacement assignments. reject this path without
		// claiming that control revoked the retained subject's authority.
		return connectorClaim{}, &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
	}
	message, err := proof.RelayClaimMessage(source)
	if err != nil {
		return connectorClaim{}, denied
	}
	started := time.Now()
	claim, err := a.Claim.ClaimConnectorPeerPairLegFromAcceptedSocket(ctx, lease, source, proof, ed25519.Sign(a.SigningKey, message))
	if err != nil {
		return connectorClaim{}, err
	}
	key, keyErr := base64.RawURLEncoding.Strict().DecodeString(claim.Key)
	defer clear(key)
	duration := claim.ExpiresAt.Sub(claim.ObservedAt)
	until := started.Add(duration)
	state := tunnelv1.ConnectorPeerLegBindingState(claim.BindingState)
	_, idErr := tunnelv1.ParsePeerDeliveryIdentifier(claim.DeliveryId)
	if claim.PairId != proof.PairID || claim.DeliveryGeneration != proof.DeliveryGeneration || claim.ConnectionSlot != proof.ConnectionSlot || claim.SourceIp != source.String() ||
		(state != tunnelv1.ConnectorPeerLegBindingActive && state != tunnelv1.ConnectorPeerLegBindingPrepared) ||
		state == tunnelv1.ConnectorPeerLegBindingPrepared && duration > 10*time.Second ||
		keyErr != nil || len(key) != 32 || idErr != nil || claim.ObservedAt.IsZero() || duration <= 0 || duration > 5*time.Minute || !until.After(time.Now()) {
		return connectorClaim{}, denied
	}
	if _, current := a.currentLease(proof); !current {
		return connectorClaim{}, &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
	}
	if err := observed.check(); err != nil {
		return connectorClaim{}, err
	}
	r := connectorClaim{source: observed, receipt: tunnelv1.ConnectorPairLegAccepted{PairID: claim.PairId, DeliveryID: claim.DeliveryId, DeliveryGeneration: claim.DeliveryGeneration, BindingState: state, ConnectionSlot: claim.ConnectionSlot, SourceIP: claim.SourceIp, ObservedAt: time.Now(), ExpiresAt: until}}
	if proof.PublicURLID != "" {
		r.public = tunnelv1.PublisherConnectionRef{PublicURLID: proof.PublicURLID, PublishRunID: proof.PublishRunID, PublishRunNumber: uint64(proof.PublishRunNumber),
			PublisherConnectionID: proof.PublisherConnectionID, ConnectionSlot: uint8(proof.ConnectionSlot), ConnectionAssignmentRevision: uint64(proof.AssignmentRevision), RelayServiceID: proof.RelayServiceID}
	} else {
		r.ref = tunnelv1.ServicePublisherConnectionRef{ServiceID: proof.ServiceID, ServiceRunID: proof.ServiceRunID, RunNumber: uint64(proof.RunNumber),
			PublisherConnectionID: proof.PublisherConnectionID, ConnectionSlot: uint8(proof.ConnectionSlot), ConnectionAssignmentRevision: uint64(proof.AssignmentRevision), RelayServiceID: proof.RelayServiceID}
	}
	copy(r.key[:], key)
	if r.key == [32]byte{} {
		return connectorClaim{}, denied
	}
	return r, nil
}

func (a *ConnectorAcceptor) serve(ctx context.Context, outer muxsession.Session, session *tunnel.Session, proof tunnelv1.ConnectorPairLegProof, claim connectorClaim) error {
	lease, valid := a.currentLease(proof)
	publisher, present := a.publisherPackets(claim, lease)
	if !valid || !present {
		return &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
	}
	packets, err := newConnectorPacketSession(ctx, outer)
	if err != nil {
		return err
	}
	defer packets.Close()
	if claim.source == nil {
		return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	}
	d := newConnectorDelivery(ctx, publisher.Done(), proof, claim)
	defer d.close()
	id, _ := tunnelv1.ParsePeerDeliveryIdentifier(claim.receipt.DeliveryID)
	carrier, err := packets.Register(peerBinding(claim, id, 1, d.admit), false)
	if err != nil {
		return err
	}
	defer carrier.Close()
	d.carrier = newConnectorBindingCarrier(carrier, claim.source, d.admit, d.cancel)
	return session.HandleConnectorLegControl(d.ctx, func(ctx context.Context, selection tunnelv1.ConnectorLegBinding) error {
		_, err := publisher.selectBridge(ctx, a, d, id, selection)
		return err
	}, func(ctx context.Context, proof tunnelv1.ConnectorPairLegProof) (tunnelv1.ConnectorPairLegAccepted, error) {
		return d.renew(ctx, a, outer, proof)
	})
}
