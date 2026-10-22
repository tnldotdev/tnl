package tunnel

import "github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"

// PublicForwardingRef projects assignment identity only. relay process identity,
// lease liveness and visitor authorization remain separate checks.
func PublicForwardingRef(h tunnelv1.InternalForwardingHeader) tunnelv1.PublisherConnectionRef {
	return tunnelv1.PublisherConnectionRef{
		PublicURLID: h.PublicURLID, PublishRunID: h.PublishRunID, PublishRunNumber: h.PublishRunNumber,
		PublisherConnectionID: h.PublisherConnectionID, ConnectionSlot: h.ConnectionSlot,
		ConnectionAssignmentRevision: h.ConnectionAssignmentRevision, RelayServiceID: h.RelayServiceID,
	}
}

// ServiceForwardingRef projects the complete private assignment identity.
func ServiceForwardingRef(h tunnelv1.ServiceForwardingHeader) tunnelv1.ServicePublisherConnectionRef {
	return tunnelv1.ServicePublisherConnectionRef{
		ServiceID: h.ServiceID, ServiceRunID: h.ServiceRunID, RunNumber: h.RunNumber,
		PublisherConnectionID: h.PublisherConnectionID, ConnectionSlot: h.ConnectionSlot,
		ConnectionAssignmentRevision: h.ConnectionAssignmentRevision, RelayServiceID: h.RelayServiceID,
	}
}
