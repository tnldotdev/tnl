package service

import (
	"context"
	"encoding/base64"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// PeerBinding can only be constructed from the current run's authenticated
// control delivery. application openings and packet equality cannot mint it.
type PeerBinding struct {
	peerIdentity
	peerNetworkBinding
	peerLease
}

// peerIdentity is fixed for the lifetime of a retained inner session. lease
// renewal supplies new deadline evidence, never another identity or carrier.
type peerIdentity struct {
	pairID, serviceID, runID, publisherID string
	trustRevision                         int64
	number                                uint64
	delivery                              [16]byte
	sessionKey                            [32]byte
	subject                               tunnelv1.VisitorSubject
}

type peerNetworkBinding struct {
	generation           int64
	key                  [32]byte
	source               netip.Addr
	relays               [2]controlv1.ConnectorPeerPairRelay
	state                controlv1.ConnectorPeerPairBindingState
	operation, challenge string
}

type peerLease struct {
	until          time.Time
	authorityUntil time.Time
	observedAt     time.Time
}

func (PeerBinding) String() string   { return "connector peer binding" }
func (PeerBinding) GoString() string { return "connector peer binding" }

type peerDeliveryControl interface {
	DeliverConnectorPeerPair(context.Context, string, string, string, int64, credentials.ServiceRunToken) (controlv1.ConnectorPeerPairDelivery, error)
}

// PreparePeerBinding runs before application arrival. request transit spends
// the returned authority interval; application input never selects source IP.
func PreparePeerBinding(ctx context.Context, control peerDeliveryControl, serviceID, runID, pairID string, generation int64, token credentials.ServiceRunToken) (PeerBinding, error) {
	if control == nil || !opaqueid.Valid(serviceID, opaqueid.ServicePrefix) || !opaqueid.Valid(runID, opaqueid.ServiceRunPrefix) || !opaqueid.Valid(pairID, "cpp_") || generation < 1 || token == "" {
		return PeerBinding{}, ErrPrivateStream
	}
	started := time.Now()
	d, err := control.DeliverConnectorPeerPair(ctx, serviceID, runID, pairID, generation, token)
	if err != nil {
		return PeerBinding{}, err
	}
	id, idErr := tunnelv1.ParsePeerDeliveryIdentifier(d.DeliveryId)
	key, keyErr := base64.RawURLEncoding.Strict().DecodeString(d.Key)
	defer clear(key)
	sessionKey, sessionKeyErr := base64.RawURLEncoding.Strict().DecodeString(d.SessionKey)
	defer clear(sessionKey)
	source, sourceErr := netip.ParseAddr(d.SourceIp)
	subject, subjectErr := visitorsubject.Parse(d.Subject)
	duration := d.ExpiresAt.Sub(d.ObservedAt)
	sourceValid := sourceErr == nil && source.IsValid() && !source.IsUnspecified() && source.Zone() == "" && source.Unmap().String() == d.SourceIp
	if idErr != nil || keyErr != nil || len(key) != 32 || sessionKeyErr != nil || len(sessionKey) != 32 || d.TrustRevision < 1 || !d.BindingState.Valid() || (!sourceValid && (d.BindingState == controlv1.ConnectorPeerPairBindingActive || d.SourceIp != "")) || subjectErr != nil ||
		d.PairId != pairID || d.ServiceId != serviceID || d.ServiceRunId != runID || d.DeliveryGeneration != generation || d.RunNumber < 1 ||
		!opaqueid.Valid(d.PublisherIdentityId, opaqueid.PublisherIdentityPrefix) || len(d.Relays) != 2 || d.ObservedAt.IsZero() || duration <= 0 || duration > 5*time.Minute || !started.Add(duration).After(time.Now()) || ctx.Err() != nil {
		return PeerBinding{}, ErrPrivateStream
	}
	b := PeerBinding{peerIdentity: peerIdentity{pairID: pairID, serviceID: serviceID, runID: runID, publisherID: d.PublisherIdentityId,
		number: uint64(d.RunNumber), delivery: id, subject: subject, trustRevision: d.TrustRevision},
		peerNetworkBinding: peerNetworkBinding{generation: generation, source: source, state: d.BindingState, operation: d.OperationId, challenge: d.BindingChallenge},
		peerLease:          peerLease{until: started.Add(duration), authorityUntil: d.ExpiresAt, observedAt: d.ObservedAt}}
	copy(b.key[:], key)
	copy(b.sessionKey[:], sessionKey)
	copy(b.relays[:], d.Relays)
	if b.operation != "" || b.state != controlv1.ConnectorPeerPairBindingActive {
		challenge, challengeErr := base64.RawURLEncoding.Strict().DecodeString(b.challenge)
		if !opaqueid.Valid(b.operation, opaqueid.IdempotencyPrefix) || challengeErr != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != b.challenge {
			return PeerBinding{}, ErrPrivateStream
		}
	}
	if b.key == [32]byte{} || b.sessionKey == [32]byte{} || b.key == b.sessionKey || base64.RawURLEncoding.EncodeToString(b.key[:]) != d.Key || base64.RawURLEncoding.EncodeToString(b.sessionKey[:]) != d.SessionKey || b.relays[0].PublisherConnectionId == b.relays[1].PublisherConnectionId || b.relays[0].RelayLease.RelayServiceId == b.relays[1].RelayLease.RelayServiceId {
		return PeerBinding{}, ErrPrivateStream
	}
	for slot, relay := range b.relays {
		ref := tunnelv1.ServicePublisherConnectionRef{ServiceID: serviceID, ServiceRunID: runID, RunNumber: b.number,
			PublisherConnectionID: relay.PublisherConnectionId, ConnectionSlot: uint8(slot), ConnectionAssignmentRevision: uint64(relay.AssignmentRevision), RelayServiceID: relay.RelayLease.RelayServiceId}
		if ref.Validate() != nil || relay.AssignmentRevision < 1 || relay.RelayLease.RelayLeaseRevision < 1 || relay.RelayLease.RelayId == "" || !opaqueid.Valid(relay.RelayLease.RelayRunId, opaqueid.RelayRunPrefix) || relay.RelayAddress == "" || relay.TlsServerName == "" {
			return PeerBinding{}, ErrPrivateStream
		}
	}
	return b, nil
}

func (b PeerBinding) expected() tunnelv1.ConnectorPeerSession {
	return tunnelv1.ConnectorPeerSession{PairID: b.pairID, DeliveryID: base64.RawURLEncoding.EncodeToString(b.delivery[:]), DeliveryGeneration: b.generation,
		ServiceID: b.serviceID, ServiceRunID: b.runID, RunNumber: b.number, Subject: b.subject, SourceIP: b.source.String(), ExpiresAt: b.until}
}

func (b *Bound) peerCurrentLocked(binding PeerBinding) bool {
	return b.peerIdentityCurrentLocked(binding.peerIdentity) && binding.until.After(time.Now()) &&
		(binding.state != controlv1.ConnectorPeerPairBindingActive || binding.expected().Validate() == nil) && binding.key != [32]byte{}
}

func (b *Bound) peerIdentityCurrentLocked(identity peerIdentity) bool {
	return !b.closed && b.prepared.policy != nil && identity.sessionKey != [32]byte{} && identity.trustRevision == b.prepared.metadataRevision &&
		identity.serviceID == b.prepared.Preparation.ServiceId && identity.runID == b.prepared.Preparation.ServiceRunId &&
		identity.number == uint64(b.prepared.Preparation.RunNumber) && identity.publisherID == b.prepared.Preparation.PublisherIdentityId
}

// assignment checks apply only to delivery; they do not define owner lifetime.
func (b *Bound) peerRelaysCurrentLocked(binding PeerBinding) bool {
	for slot, relay := range binding.relays {
		current := b.connections[slot]
		if current.PublisherConnectionId != relay.PublisherConnectionId || current.ConnectionAssignmentRevision != relay.AssignmentRevision || current.RelayServiceId != relay.RelayLease.RelayServiceId || current.RelayAddress != relay.RelayAddress || current.TlsServerName != relay.TlsServerName {
			return false
		}
	}
	return true
}
