package tunnel

import "github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"

// ServiceForwardingRef projects assignment identity only. relay process
// identity, lease liveness and visitor authorization remain separate checks.
func ServiceForwardingRef(h tunnelv1.ServiceForwardingHeader) tunnelv1.ServicePublisherConnectionRef {
	return tunnelv1.ServicePublisherConnectionRef{
		ServiceID: h.ServiceID, ServiceRunID: h.ServiceRunID, RunNumber: h.RunNumber,
		PublisherConnectionID: h.PublisherConnectionID, ConnectionSlot: h.ConnectionSlot,
		ConnectionAssignmentRevision: h.ConnectionAssignmentRevision, RelayServiceID: h.RelayServiceID,
	}
}
