package observability

// ServiceAuditCount accepts fixed outcomes only; IDs, IPs and errors are never
// metric labels. dropped includes overflow, invalid input and shutdown loss.
func (m *Metrics) ServiceAuditCount(result string, n uint64) {
	if m == nil || n == 0 {
		return
	}
	switch result {
	case "queued", "delivered", "retry", "dropped", "accepted", "duplicate":
		m.serviceAudit.With(eventDimension(result)).Add(float64(n))
	}
}
