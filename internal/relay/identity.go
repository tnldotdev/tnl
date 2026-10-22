package relay

import (
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func publicClaimRef(c relayv1.ClaimedPublisherConnection) tunnelv1.PublisherConnectionRef {
	return tunnelv1.PublisherConnectionRef{PublicURLID: c.PublicUrlId, PublishRunID: c.PublishRunId, PublishRunNumber: uint64(c.PublishRunNumber),
		PublisherConnectionID: c.PublisherConnectionId, ConnectionSlot: uint8(c.ConnectionSlot),
		ConnectionAssignmentRevision: uint64(c.ConnectionAssignmentRevision), RelayServiceID: c.RelayServiceId}
}

func publicTransitionRef(c relayv1.PublisherConnectionTransition) tunnelv1.PublisherConnectionRef {
	return tunnelv1.PublisherConnectionRef{PublicURLID: c.PublicUrlId, PublishRunID: c.PublishRunId, PublishRunNumber: uint64(c.PublishRunNumber),
		PublisherConnectionID: c.PublisherConnectionId, ConnectionSlot: uint8(c.ConnectionSlot),
		ConnectionAssignmentRevision: uint64(c.ConnectionAssignmentRevision), RelayServiceID: c.RelayServiceId}
}

func privateClaimRef(c relayv1.ServicePublisherConnection, slot uint8) tunnelv1.ServicePublisherConnectionRef {
	// the control response has no slot; retain the slot authenticated by the
	// publisher hello, and compare every field that control returns.
	return tunnelv1.ServicePublisherConnectionRef{ServiceID: c.ServiceId, ServiceRunID: c.ServiceRunId, RunNumber: uint64(c.RunNumber),
		PublisherConnectionID: c.PublisherConnectionId, ConnectionSlot: slot,
		ConnectionAssignmentRevision: uint64(c.ConnectionAssignmentRevision), RelayServiceID: c.RelayServiceId}
}
