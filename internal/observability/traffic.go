package observability

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
	m.trafficAdmissions.WithLabelValues(stage, result).Inc()
}
