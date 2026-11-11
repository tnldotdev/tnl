package observability

// ServerOperation names authored server work, never wire values or resource IDs.
type ServerOperation uint8

const (
	OpCreatePublishRun ServerOperation = iota + 1
	OpHeartbeatPublishRun
	OpClosePublishRun
	OpReadIngressRoutingTableSnapshot
	OpReadIngressRoutingTableEvents
	OpRefreshPortPoolMetrics
	OpAdvanceIngressRoutingRetention
	OpPruneIngressRoutingHistory
	OpRenewIngress
	OpClaimPublisherConnection
	OpMarkPublisherConnectionReady
	OpCompanyAuthorizeSession
	OpOIDCVerify
	OpOIDCDiscovery
	OpOIDCRedeem
	OpPublisherRuntimeInspect
	OpPublisherRuntimeStart
	OpPublisherRuntimeRenew
	OpPublisherRuntimeStop
	OpPublisherRuntimeInvalid
	OpIngressRegister
	OpIngressFetchSnapshot
	OpIngressFetchEvents
	OpIngressRenewLease
	OpIngressApplySnapshot
	OpIngressApplyEvents
	OpIngressRelayConnect
	OpIngressForwardingAck
	OpIngressForwardingCleanup
	OpIngressBackendAttempt
	OpIngressBackendCleanup
	OpIngressFallback
	OpRelayRegister
	OpRelayRenewLease
	OpRelayBeginDrain
	OpRelayDrain
	OpRelayAdmitPublisherConnection
	OpRelayOpenVisitorStream
	OpRelayDisconnectPublisherConnection
)

var serverOperations = []operationName{
	"", "CreatePublishRun", "HeartbeatPublishRun", "ClosePublishRun",
	"ReadIngressRoutingTableSnapshot", "ReadIngressRoutingTableEvents", "RefreshPortPoolMetrics",
	"AdvanceIngressRoutingRetention", "PruneIngressRoutingHistory", "RenewIngress",
	"ClaimPublisherConnection", "MarkPublisherConnectionReady", "company.authorize_session",
	"oidc.verify", "oidc.discovery", "oidc.redeem", "publisher_runtime.inspect",
	"publisher_runtime.start", "publisher_runtime.renew", "publisher_runtime.stop", "publisher_runtime.invalid",
	"IngressRegister", "IngressFetchSnapshot", "IngressFetchEvents", "IngressRenewLease",
	"IngressApplySnapshot", "IngressApplyEvents", "IngressRelayConnect", "IngressForwardingAck",
	"IngressForwardingCleanup", "IngressBackendAttempt", "IngressBackendCleanup", "IngressFallback",
	"RelayRegister", "RelayRenewLease", "RelayBeginDrain", "RelayDrain",
	"RelayAdmitPublisherConnection", "RelayOpenVisitorStream", "RelayDisconnectPublisherConnection",
}

func (v ServerOperation) operation() operationName {
	if int(v) >= len(serverOperations) {
		return ""
	}
	return serverOperations[v]
}

func (v ServerOperation) String() string { return v.operation().String() }

func apiOperation(surface string) operationName {
	switch surface {
	case "control":
		return "tnl.control.request"
	case "authority":
		return "tnl.authority.request"
	case "ingress":
		return "tnl.ingress.request"
	case "relay":
		return "tnl.relay.request"
	case "private_ingress":
		return "tnl.private_ingress.request"
	case "private_relay":
		return "tnl.private_relay.request"
	default:
		return ""
	}
}
