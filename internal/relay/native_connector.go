package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// NativeConnectorAcceptor attests the directly accepted socket source and owns
// bounded native relay candidates. no opening supplies source
// authority. activation alone selects a candidate for packet delivery.
type NativeConnectorAcceptor struct {
	CurrentLease func() relayv1.RelayLease
	SigningKey   ed25519.PrivateKey
	Claim        NativePeerLegClaimClient
	Publishers   *ServiceRegistry
	mu           sync.Mutex
	sessions     int
	legs         map[nativeLegID]int
}

type nativeLegID struct {
	pair       string
	generation int64
	slot       int
}

const maxNativeConnectorSessions = 64

func (a *NativeConnectorAcceptor) reserve(proof tunnelv1.NativePairLegProof) (func(), error) {
	if a == nil || a.CurrentLease == nil || a.Claim == nil || a.Publishers == nil || len(a.SigningKey) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(a.SigningKey.Seed()), a.SigningKey) {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	}
	id := nativeLegID{proof.PairID, proof.DeliveryGeneration, proof.ConnectionSlot}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sessions >= maxNativeConnectorSessions || a.legs[id] >= 2 {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
	}
	if a.legs == nil {
		a.legs = make(map[nativeLegID]int)
	}
	a.sessions++
	a.legs[id]++
	return sync.OnceFunc(func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.sessions--
		a.legs[id]--
		if a.legs[id] == 0 {
			delete(a.legs, id)
		}
	}), nil
}

type nativeConnectorClaim struct {
	receipt tunnelv1.NativePairLegAccepted
	ref     tunnelv1.ServicePublisherConnectionRef
	key     [32]byte
}

func (nativeConnectorClaim) String() string   { return "native connector claim" }
func (nativeConnectorClaim) GoString() string { return "native connector claim" }

func (a *NativeConnectorAcceptor) currentLease(proof tunnelv1.NativePairLegProof) (relayv1.RelayLease, bool) {
	lease := a.CurrentLease()
	valid := lease.RelayServiceId == proof.RelayServiceID && lease.RelayId == proof.RelayID && lease.RelayRunId == proof.RelayRunID && lease.RelayLeaseRevision > 0 && uint64(lease.RelayLeaseRevision) == proof.RelayLeaseRevision &&
		!lease.Draining && lease.LeaseExpiresAt.After(time.Now()) && lease.PeerSigningPublicKey != nil && *lease.PeerSigningPublicKey == base64.RawURLEncoding.EncodeToString(a.SigningKey.Public().(ed25519.PublicKey))
	return lease, valid
}

func (a *NativeConnectorAcceptor) claim(ctx context.Context, outer muxsession.Session, proof tunnelv1.NativePairLegProof) (nativeConnectorClaim, error) {
	denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	accepted, ok := outer.(muxsession.AcceptedPeer)
	if !ok || proof.Validate() != nil {
		return nativeConnectorClaim{}, denied
	}
	address := accepted.RemoteAddr()
	switch socket := address.(type) {
	case *net.TCPAddr:
		if socket == nil {
			return nativeConnectorClaim{}, denied
		}
	case *net.UDPAddr:
		if socket == nil {
			return nativeConnectorClaim{}, denied
		}
	default:
		return nativeConnectorClaim{}, denied
	}
	socket, err := netip.ParseAddrPort(address.String())
	if err != nil || socket.Addr().IsUnspecified() || socket.Addr().Zone() != "" {
		return nativeConnectorClaim{}, denied
	}
	source := socket.Addr().Unmap()
	lease, valid := a.currentLease(proof)
	if !valid {
		return nativeConnectorClaim{}, denied
	}
	message, err := proof.RelayClaimMessage(source)
	if err != nil {
		return nativeConnectorClaim{}, denied
	}
	started := time.Now()
	claim, err := a.Claim.ClaimNativePeerPairLegFromAcceptedSocket(ctx, lease, source, proof, ed25519.Sign(a.SigningKey, message))
	if err != nil {
		return nativeConnectorClaim{}, errors.Join(err, denied)
	}
	key, keyErr := base64.RawURLEncoding.Strict().DecodeString(claim.Key)
	defer clear(key)
	duration := claim.ExpiresAt.Sub(claim.ObservedAt)
	until := started.Add(duration)
	_, idErr := tunnelv1.ParsePeerDeliveryIdentifier(claim.DeliveryId)
	if claim.PairId != proof.PairID || claim.DeliveryGeneration != proof.DeliveryGeneration || claim.ConnectionSlot != proof.ConnectionSlot || claim.SourceIp != source.String() ||
		keyErr != nil || len(key) != 32 || idErr != nil || claim.ObservedAt.IsZero() || duration <= 0 || duration > 5*time.Minute || !until.After(time.Now()) || ctx.Err() != nil {
		return nativeConnectorClaim{}, denied
	}
	if _, current := a.currentLease(proof); !current {
		return nativeConnectorClaim{}, denied
	}
	r := nativeConnectorClaim{receipt: tunnelv1.NativePairLegAccepted{PairID: claim.PairId, DeliveryID: claim.DeliveryId, DeliveryGeneration: claim.DeliveryGeneration, ConnectionSlot: claim.ConnectionSlot, SourceIP: claim.SourceIp, ObservedAt: time.Now(), ExpiresAt: until},
		ref: tunnelv1.ServicePublisherConnectionRef{ServiceID: proof.ServiceID, ServiceRunID: proof.ServiceRunID, RunNumber: uint64(proof.RunNumber), PublisherConnectionID: proof.PublisherConnectionID, ConnectionSlot: uint8(proof.ConnectionSlot), ConnectionAssignmentRevision: uint64(proof.AssignmentRevision), RelayServiceID: proof.RelayServiceID}}
	copy(r.key[:], key)
	if r.key == [32]byte{} {
		return nativeConnectorClaim{}, denied
	}
	return r, nil
}

func (a *NativeConnectorAcceptor) serve(ctx context.Context, outer muxsession.Session, session *tunnel.Session, proof tunnelv1.NativePairLegProof, claim nativeConnectorClaim) error {
	lease, valid := a.currentLease(proof)
	connection, present := a.Publishers.nativeCandidate(claim.ref, lease)
	if !valid || !present {
		return &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
	}
	packets, err := newNativePacketSession(ctx, outer)
	if err != nil {
		return err
	}
	defer packets.Close()
	id, _ := tunnelv1.ParsePeerDeliveryIdentifier(claim.receipt.DeliveryID)
	carrier, err := packets.Register(peerBinding(claim, id, 1), false)
	if err != nil {
		return err
	}
	defer carrier.Close()
	life, cancel := context.WithCancel(ctx)
	defer cancel()
	d := &nativeDelivery{ctx: life, cancel: cancel, claim: claim, proof: proof, connection: connection, carrier: carrier, until: claim.receipt.ExpiresAt, changed: make(chan struct{})}
	watchDone := make(chan struct{})
	go func() { defer close(watchDone); d.watch(a) }()
	defer func() {
		cancel()
		<-watchDone
		if d.bridge != nil {
			d.bridge.detach(d)
		}
	}()
	return session.HandleNativeLegControl(life, func(ctx context.Context, selection tunnelv1.NativeLegBinding) error {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.ctx.Err() != nil || !d.until.After(time.Now()) || d.bridge != nil {
			return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
		}
		var err error
		d.bridge, err = connection.packets.selectBridge(ctx, a, d, id, selection)
		return err
	}, func(ctx context.Context, proof tunnelv1.NativePairLegProof) (tunnelv1.NativePairLegAccepted, error) {
		return d.renew(ctx, a, outer, proof)
	})
}
