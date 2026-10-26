package observability

func (m *Metrics) ObserveSTUNBinding(result string) {
	if m == nil {
		return
	}
	switch result {
	case "accepted", "invalid", "capacity", "transport_error":
		m.stunBindings.With(resultDimension(result)).Inc()
	}
}

func (m *Metrics) ObserveTrafficAdmission(stage, result string) {
	switch stage {
	case "source", "ordinary", "pending", "promotion", "bytes":
	default:
		return
	}
	switch result {
	case "accepted", "capacity", "stale", "expired", "bandwidth", "invalid":
	default:
		return
	}
	m.trafficAdmissions.With(Operation.Dimension(operationName(stage)), resultDimension(result)).Inc()
}
