package service

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// PeerBinding is local delivery material for a future run owner. it is never
// logged or persisted and does not authorize accepting an application stream.
type PeerBinding struct {
	pairID, serviceID, serviceRunID, publisherIdentityID string
	runNumber, generation                                int64
	subject                                              controlv1.VisitorSubject
	deliveryID                                           [16]byte
	key                                                  [32]byte
	sourceIP                                             netip.Addr
	relays                                               [2]controlv1.NativePeerPairRelay
	expiresAt                                            time.Time
}

func (PeerBinding) String() string   { return "native peer binding" }
func (PeerBinding) GoString() string { return "native peer binding" }

func (b PeerBinding) PairID() string                           { return b.pairID }
func (b PeerBinding) ServiceID() string                        { return b.serviceID }
func (b PeerBinding) ServiceRunID() string                     { return b.serviceRunID }
func (b PeerBinding) PublisherIdentityID() string              { return b.publisherIdentityID }
func (b PeerBinding) RunNumber() int64                         { return b.runNumber }
func (b PeerBinding) Generation() int64                        { return b.generation }
func (b PeerBinding) DeliveryID() [16]byte                     { return b.deliveryID }
func (b PeerBinding) Key() [32]byte                            { return b.key }
func (b PeerBinding) SourceIP() netip.Addr                     { return b.sourceIP }
func (b PeerBinding) Relays() [2]controlv1.NativePeerPairRelay { return b.relays }
func (b PeerBinding) ExpiresAt() time.Time                     { return b.expiresAt }
func (b PeerBinding) Subject() controlv1.VisitorSubject {
	s := b.subject
	if s.IdentityId != nil {
		id := *s.IdentityId
		s.IdentityId = &id
	}
	if s.DeviceId != nil {
		id := *s.DeviceId
		s.DeviceId = &id
	}
	if s.WorkloadSessionId != nil {
		id := *s.WorkloadSessionId
		s.WorkloadSessionId = &id
	}
	return s
}

type peerDeliveryControl interface {
	DeliverNativePeerPair(context.Context, string, string, string, int64, credentials.ServiceRunToken) (controlv1.NativePeerPairDelivery, error)
}

// PreparePeerBinding checks the exact requested delivery before handing its
// immutable values to the run owner. the server alone chooses the source IP.
func PreparePeerBinding(ctx context.Context, control peerDeliveryControl, serviceID, runID, pairID string, generation int64, token credentials.ServiceRunToken) (PeerBinding, error) {
	var result PeerBinding
	if control == nil || !opaqueid.Valid(serviceID, opaqueid.ServicePrefix) || !opaqueid.Valid(runID, opaqueid.ServiceRunPrefix) || !opaqueid.Valid(pairID, "npp_") || generation < 1 || token == "" {
		return result, ErrPrivateStream
	}
	started := time.Now()
	delivery, err := control.DeliverNativePeerPair(ctx, serviceID, runID, pairID, generation, token)
	if err != nil {
		return result, err
	}
	id, err := tunnelv1.ParsePeerDeliveryIdentifier(delivery.DeliveryId)
	key, keyErr := base64.RawURLEncoding.Strict().DecodeString(delivery.Key)
	defer clear(key)
	source, sourceErr := netip.ParseAddr(delivery.SourceIp)
	duration := delivery.ExpiresAt.Sub(delivery.ObservedAt)
	if err != nil || keyErr != nil || len(key) != len(result.key) || base64.RawURLEncoding.EncodeToString(key) != delivery.Key || sourceErr != nil || !source.IsValid() || source.IsUnspecified() || source.Unmap().String() != delivery.SourceIp || source.Zone() != "" ||
		delivery.PairId != pairID || delivery.ServiceId != serviceID || delivery.ServiceRunId != runID || delivery.DeliveryGeneration != generation ||
		delivery.RunNumber < 1 || !opaqueid.Valid(delivery.PublisherIdentityId, opaqueid.PublisherIdentityPrefix) || len(delivery.Relays) != 2 ||
		delivery.ObservedAt.IsZero() || duration <= 0 || duration > 5*time.Minute || !started.Add(duration).After(time.Now()) || ctx.Err() != nil {
		return PeerBinding{}, errors.New("publisher: invalid native peer pair delivery")
	}
	result.pairID, result.serviceID, result.serviceRunID, result.publisherIdentityID = pairID, serviceID, runID, delivery.PublisherIdentityId
	result.runNumber, result.generation, result.subject = delivery.RunNumber, generation, delivery.Subject
	result.subject = result.Subject()
	result.deliveryID, result.sourceIP, result.expiresAt = id, source, started.Add(duration)
	copy(result.key[:], key)
	copy(result.relays[:], delivery.Relays)
	if !result.valid(time.Now()) {
		return PeerBinding{}, ErrPrivateStream
	}
	return result, nil
}

func (b PeerBinding) valid(now time.Time) bool {
	if !opaqueid.Valid(b.pairID, "npp_") || !opaqueid.Valid(b.serviceID, opaqueid.ServicePrefix) ||
		!opaqueid.Valid(b.serviceRunID, opaqueid.ServiceRunPrefix) || !opaqueid.Valid(b.publisherIdentityID, opaqueid.PublisherIdentityPrefix) ||
		b.runNumber < 1 || b.generation < 1 || b.deliveryID == [16]byte{} || b.key == [32]byte{} ||
		!b.sourceIP.IsValid() || b.sourceIP.IsUnspecified() || b.sourceIP.Is4In6() || b.sourceIP.Zone() != "" || !b.expiresAt.After(now) {
		return false
	}
	if _, err := visitorsubject.Parse(b.subject); err != nil {
		return false
	}
	if b.relays[0].PublisherConnectionId == b.relays[1].PublisherConnectionId ||
		b.relays[0].RelayLease.RelayServiceId == b.relays[1].RelayLease.RelayServiceId ||
		b.relays[0].RelayLease.RelayId == b.relays[1].RelayLease.RelayId {
		return false
	}
	for slot, relay := range b.relays {
		ref := tunnelv1.ServicePublisherConnectionRef{ServiceID: b.serviceID, ServiceRunID: b.serviceRunID, RunNumber: uint64(b.runNumber),
			PublisherConnectionID: relay.PublisherConnectionId, ConnectionSlot: uint8(slot),
			ConnectionAssignmentRevision: uint64(relay.AssignmentRevision), RelayServiceID: relay.RelayLease.RelayServiceId}
		if ref.Validate() != nil || relay.AssignmentRevision < 1 || relay.RelayLease.RelayLeaseRevision < 1 ||
			relay.RelayLease.RelayId == "" || relay.RelayLease.RelayRunId == "" || relay.RelayAddress == "" || relay.TlsServerName == "" {
			return false
		}
	}
	return true
}
