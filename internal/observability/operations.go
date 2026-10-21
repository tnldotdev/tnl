package observability

// control callers also use this adapter from wrappers with dynamic arguments.
// only existing authored names cross into the typed span/metric boundary.
func controlOperationName(value string) (operationName, bool) {
	switch value {
	case "CreatePublishRun", "HeartbeatPublishRun", "ClosePublishRun",
		"ReadIngressRoutingTableSnapshot", "ReadIngressRoutingTableEvents",
		"RefreshPortPoolMetrics", "AdvanceIngressRoutingRetention", "PruneIngressRoutingHistory",
		"ReportIngressUsage", "RenewIngress", "ClaimPublisherConnection", "MarkPublisherConnectionReady",
		"company.authorize_session", "oidc.verify", "oidc.discovery", "oidc.redeem",
		"publisher_runtime.inspect", "publisher_runtime.start", "publisher_runtime.renew", "publisher_runtime.stop", "publisher_runtime.invalid":
		return operationName(value), true
	default:
		return "", false
	}
}

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
