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

// NativeConnectorSourceMode selects the authority for the source of a native
// connector claim. zero has no source owner and cannot admit a connector.
type NativeConnectorSourceMode uint8

const (
	NativeConnectorNoSource NativeConnectorSourceMode = iota
	// NativeConnectorDirectSocket is valid only when the peer connects directly
	// to this acceptor's socket, without a load balancer or proxy in between.
	NativeConnectorDirectSocket
)

// NativeConnectorAcceptor is an opt-in owner for checked, direct-socket claims
// and optional packet delivery to exact locally claimed publisher assignments.
type NativeConnectorAcceptor struct {
	SourceMode   NativeConnectorSourceMode
	CurrentLease func() relayv1.RelayLease
	SigningKey   ed25519.PrivateKey
	Claim        NativePeerLegClaimClient
	Now          func() time.Time
	// MaxSessions limits reservations including claims in progress. zero uses
	// the finite default; the limit is separate from publisher capacity.
	MaxSessions int
	// Publishers opts into packet forwarding on exact local private assignments.
	// nil retains the bounded claim-only proof, without any packet registration.
	Publishers *ServiceRegistry

	mu       sync.Mutex
	sessions int
	legs     map[nativeConnectorLeg]int
}

const defaultNativeConnectorSessions = 64
const maxNativeConnectorLegSessions = 2

type nativeConnectorLeg struct {
	pairID     string
	generation int64
	slot       int
}

func (a *NativeConnectorAcceptor) validate() error {
	if a == nil || a.SourceMode != NativeConnectorDirectSocket || a.CurrentLease == nil || a.Claim == nil || a.MaxSessions < 0 ||
		len(a.SigningKey) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(a.SigningKey.Seed()), a.SigningKey) {
		return errors.New("relay: native connector requires a direct socket, current lease, process key, and claim client")
	}
	return nil
}

// reserve runs before the control claim, so pending claims and acknowledged
// idle sessions share the same global and exact pair/leg limits.
func (a *NativeConnectorAcceptor) reserve(proof tunnelv1.NativePairLegProof) (func(), error) {
	leg := nativeConnectorLeg{pairID: proof.PairID, generation: proof.DeliveryGeneration, slot: proof.ConnectionSlot}
	a.mu.Lock()
	limit := a.MaxSessions
	if limit == 0 {
		limit = defaultNativeConnectorSessions
	}
	if a.sessions >= limit || a.legs[leg] >= maxNativeConnectorLegSessions {
		a.mu.Unlock()
		return nil, &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
	}
	if a.legs == nil {
		a.legs = make(map[nativeConnectorLeg]int)
	}
	a.sessions++
	a.legs[leg]++
	a.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			a.sessions--
			a.legs[leg]--
			if a.legs[leg] == 0 {
				delete(a.legs, leg)
			}
			a.mu.Unlock()
		})
	}, nil
}

func (a *NativeConnectorAcceptor) admit(ctx context.Context, transport muxsession.Session, proof tunnelv1.NativePairLegProof) (nativeConnectorClaim, func(), error) {
	denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	if a.validate() != nil {
		return nativeConnectorClaim{}, nil, denied
	}
	release, err := a.reserve(proof)
	if err != nil {
		return nativeConnectorClaim{}, nil, err
	}
	claim, err := a.claim(ctx, transport, proof)
	if err != nil {
		release()
		return nativeConnectorClaim{}, nil, err
	}
	return claim, release, nil
}

// nativeConnectorClaim is constructed only after checking the accepted socket,
// current process lease and control response. its deadline is local and fixed.
type nativeConnectorClaim struct {
	receipt tunnelv1.NativePairLegAccepted
	ref     tunnelv1.ServicePublisherConnectionRef
	key     [32]byte
}

func (nativeConnectorClaim) String() string   { return "native connector claim" }
func (nativeConnectorClaim) GoString() string { return "native connector claim" }

func (a *NativeConnectorAcceptor) claim(ctx context.Context, transport muxsession.Session, proof tunnelv1.NativePairLegProof) (nativeConnectorClaim, error) {
	denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	peer, ok := transport.(muxsession.AcceptedPeer)
	if !ok {
		return nativeConnectorClaim{}, denied
	}
	// only the concrete, directly accepted socket can supply the source. SNI,
	// connector frames, STUN/ICE and unconfigured PROXY metadata have no say.
	address := peer.RemoteAddr()
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
	if err != nil || !socket.Addr().IsValid() || socket.Addr().IsUnspecified() || socket.Addr().Zone() != "" {
		return nativeConnectorClaim{}, denied
	}
	source := socket.Addr().Unmap()
	now := a.now()
	lease, ok := a.currentLease(proof, now)
	if !ok {
		return nativeConnectorClaim{}, denied
	}
	message, err := proof.RelayClaimMessage(source)
	if err != nil {
		return nativeConnectorClaim{}, denied
	}
	started := a.now()
	claim, err := a.Claim.ClaimNativePeerPairLegFromAcceptedSocket(ctx, lease, source, proof, ed25519.Sign(a.SigningKey, message))
	if err != nil {
		return nativeConnectorClaim{}, errors.Join(err, denied)
	}
	key, keyErr := base64.RawURLEncoding.Strict().DecodeString(claim.Key)
	defer clear(key)
	duration := claim.ExpiresAt.Sub(claim.ObservedAt)
	deadline := started.Add(duration)
	if claim.PairId != proof.PairID || claim.DeliveryGeneration != proof.DeliveryGeneration ||
		claim.ConnectionSlot != proof.ConnectionSlot || claim.SourceIp != source.String() ||
		keyErr != nil || len(key) != 32 || base64.RawURLEncoding.EncodeToString(key) != claim.Key ||
		claim.ObservedAt.IsZero() || duration <= 0 || duration > 5*time.Minute || !deadline.After(a.now()) || ctx.Err() != nil {
		return nativeConnectorClaim{}, denied
	}
	if _, err := tunnelv1.ParsePeerDeliveryIdentifier(claim.DeliveryId); err != nil {
		return nativeConnectorClaim{}, denied
	}
	if _, current := a.currentLease(proof, a.now()); !current {
		return nativeConnectorClaim{}, denied
	}
	result := nativeConnectorClaim{receipt: tunnelv1.NativePairLegAccepted{PairID: claim.PairId, DeliveryID: claim.DeliveryId,
		DeliveryGeneration: claim.DeliveryGeneration, ConnectionSlot: claim.ConnectionSlot,
		SourceIP: claim.SourceIp, ExpiresAt: deadline},
		ref: tunnelv1.ServicePublisherConnectionRef{ServiceID: proof.ServiceID, ServiceRunID: proof.ServiceRunID, RunNumber: uint64(proof.RunNumber),
			PublisherConnectionID: proof.PublisherConnectionID, ConnectionSlot: uint8(proof.ConnectionSlot),
			ConnectionAssignmentRevision: uint64(proof.AssignmentRevision), RelayServiceID: proof.RelayServiceID}}
	copy(result.key[:], key)
	if result.key == [32]byte{} {
		return nativeConnectorClaim{}, denied
	}
	return result, nil
}

func (a *NativeConnectorAcceptor) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *NativeConnectorAcceptor) currentLease(proof tunnelv1.NativePairLegProof, now time.Time) (relayv1.RelayLease, bool) {
	lease := a.CurrentLease()
	if lease.RelayServiceId != proof.RelayServiceID || lease.RelayId != proof.RelayID ||
		lease.RelayRunId != proof.RelayRunID || lease.RelayLeaseRevision < 1 ||
		uint64(lease.RelayLeaseRevision) != proof.RelayLeaseRevision || lease.Draining || !lease.LeaseExpiresAt.After(now) ||
		lease.PeerSigningPublicKey == nil {
		return relayv1.RelayLease{}, false
	}
	// compare the exact process key in the current lease before signing. control
	// independently verifies that lease and signature against its current state.
	if *lease.PeerSigningPublicKey != base64.RawURLEncoding.EncodeToString(a.SigningKey.Public().(ed25519.PublicKey)) {
		return relayv1.RelayLease{}, false
	}
	return lease, true
}
