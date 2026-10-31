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
	pairID, serviceID, runID, publisherID string
	generation                            int64
	number                                uint64
	delivery                              [16]byte
	key                                   [32]byte
	source                                netip.Addr
	subject                               tunnelv1.VisitorSubject
	relays                                [2]controlv1.NativePeerPairRelay
	until                                 time.Time
	authorityUntil                        time.Time
}

func (PeerBinding) String() string   { return "native peer binding" }
func (PeerBinding) GoString() string { return "native peer binding" }

type peerDeliveryControl interface {
	DeliverNativePeerPair(context.Context, string, string, string, int64, credentials.ServiceRunToken) (controlv1.NativePeerPairDelivery, error)
}

// PreparePeerBinding runs before application arrival. request transit spends
// the returned authority interval; application input never selects source IP.
func PreparePeerBinding(ctx context.Context, control peerDeliveryControl, serviceID, runID, pairID string, generation int64, token credentials.ServiceRunToken) (PeerBinding, error) {
	if control == nil || !opaqueid.Valid(serviceID, opaqueid.ServicePrefix) || !opaqueid.Valid(runID, opaqueid.ServiceRunPrefix) || !opaqueid.Valid(pairID, "npp_") || generation < 1 || token == "" {
		return PeerBinding{}, ErrPrivateStream
	}
	started := time.Now()
	d, err := control.DeliverNativePeerPair(ctx, serviceID, runID, pairID, generation, token)
	if err != nil {
		return PeerBinding{}, err
	}
	id, idErr := tunnelv1.ParsePeerDeliveryIdentifier(d.DeliveryId)
	key, keyErr := base64.RawURLEncoding.Strict().DecodeString(d.Key)
	defer clear(key)
	source, sourceErr := netip.ParseAddr(d.SourceIp)
	subject, subjectErr := visitorsubject.Parse(d.Subject)
	duration := d.ExpiresAt.Sub(d.ObservedAt)
	if idErr != nil || keyErr != nil || len(key) != 32 || sourceErr != nil || !source.IsValid() || source.IsUnspecified() || source.Zone() != "" || source.Unmap().String() != d.SourceIp || subjectErr != nil ||
		d.PairId != pairID || d.ServiceId != serviceID || d.ServiceRunId != runID || d.DeliveryGeneration != generation || d.RunNumber < 1 ||
		!opaqueid.Valid(d.PublisherIdentityId, opaqueid.PublisherIdentityPrefix) || len(d.Relays) != 2 || d.ObservedAt.IsZero() || duration <= 0 || duration > 5*time.Minute || !started.Add(duration).After(time.Now()) || ctx.Err() != nil {
		return PeerBinding{}, ErrPrivateStream
	}
	b := PeerBinding{pairID: pairID, serviceID: serviceID, runID: runID, publisherID: d.PublisherIdentityId,
		generation: generation, number: uint64(d.RunNumber), delivery: id, source: source, subject: subject, until: started.Add(duration), authorityUntil: d.ExpiresAt}
	copy(b.key[:], key)
	copy(b.relays[:], d.Relays)
	if b.key == [32]byte{} || b.relays[0].PublisherConnectionId == b.relays[1].PublisherConnectionId || b.relays[0].RelayLease.RelayServiceId == b.relays[1].RelayLease.RelayServiceId {
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

func (b PeerBinding) expected() tunnelv1.NativePeerSession {
	return tunnelv1.NativePeerSession{PairID: b.pairID, DeliveryID: base64.RawURLEncoding.EncodeToString(b.delivery[:]), DeliveryGeneration: b.generation,
		ServiceID: b.serviceID, ServiceRunID: b.runID, RunNumber: b.number, Subject: b.subject, SourceIP: b.source.String(), ExpiresAt: b.until}
}

func (b *Bound) peerCurrentLocked(binding PeerBinding) bool {
	if b.closed || b.prepared.policy == nil || !binding.until.After(time.Now()) || binding.expected().Validate() != nil || binding.key == [32]byte{} ||
		binding.serviceID != b.prepared.Preparation.ServiceId || binding.runID != b.prepared.Preparation.ServiceRunId || binding.number != uint64(b.prepared.Preparation.RunNumber) || binding.publisherID != b.prepared.Preparation.PublisherIdentityId {
		return false
	}
	return true
}

// a changed assignment requires a new pair and inner session. an existing native
// admission cannot borrow a publisher replacement's source or relay authority.
func (b *Bound) peerRelaysCurrentLocked(binding PeerBinding) bool {
	for slot, relay := range binding.relays {
		current := b.connections[slot]
		if current.PublisherConnectionId != relay.PublisherConnectionId || current.ConnectionAssignmentRevision != relay.AssignmentRevision || current.RelayServiceId != relay.RelayLease.RelayServiceId || current.RelayAddress != relay.RelayAddress || current.TlsServerName != relay.TlsServerName {
			return false
		}
	}
	return true
}
