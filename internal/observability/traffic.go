package observability

func (m *Metrics) ObserveTrafficAdmission(stage, result string) {
	if m == nil {
		return
	}
	switch stage {
	case "source", "ordinary", "pending", "promotion", "bytes":
	default:
		return
	}
	outcome := semanticResult{outcome: Rejected}
	switch result {
	case "accepted":
		outcome.outcome = Success
	case "capacity":
		outcome.reason = ReasonCapacity
	case "stale":
		outcome.reason = ReasonStale
	case "expired":
		outcome = semanticResult{Error, ReasonExpired}
	case "bandwidth":
		outcome.reason = ReasonBandwidth
	case "invalid":
		outcome.reason = ReasonInvalid
	default:
		return
	}
	m.trafficAdmissions.With(Operation.Dimension(operationName(stage)), outcome.dimension()).Inc()
}
