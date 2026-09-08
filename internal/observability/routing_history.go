package observability

func (m *Metrics) ObserveRoutingHistoryFloor(revision uint64) {
	if m == nil {
		return
	}
	for previous := m.routingHistoryFloor.Load(); revision > previous; previous = m.routingHistoryFloor.Load() {
		if m.routingHistoryFloor.CompareAndSwap(previous, revision) {
			return
		}
	}
}

func (m *Metrics) ObserveRoutingHistoryBatch(scanned, deleted int64, busy bool) {
	if m == nil {
		return
	}
	if busy {
		m.routingHistorySkipped.Inc()
		return
	}
	m.routingHistoryRows.WithLabelValues("scanned").Add(float64(scanned))
	m.routingHistoryRows.WithLabelValues("deleted").Add(float64(deleted))
}
