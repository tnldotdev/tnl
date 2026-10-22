package relay

import (
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
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

func privateClaimRef(c relayv1.PrivatePublisherConnection, slot uint8) tunnelv1.PrivatePublisherConnectionRef {
	// the control response has no slot; retain the slot authenticated by the
	// publisher hello, and compare every field that control returns.
	return tunnelv1.PrivatePublisherConnectionRef{PrivateServiceID: c.PrivateServiceId, PrivateRunID: c.PrivateRunId, RunNumber: uint64(c.RunNumber),
		PublisherConnectionID: c.PublisherConnectionId, ConnectionSlot: slot,
		ConnectionAssignmentRevision: uint64(c.ConnectionAssignmentRevision), RelayServiceID: c.RelayServiceId}
}
