package controlstate

import (
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

// Instrument sends completed state operations and request-pool queries to one
// process registry. configure it after Open and before serving requests.
func (d *Database) Instrument(metrics *observability.Metrics) {
	d.activity.metrics.Store(metrics)
}

// PrometheusMetrics supplies the same passive database snapshot to runtime
// scrapes and local load tests. it never acquires a database connection.
func (d *Database) PrometheusMetrics(now time.Time) observability.DatabaseSnapshot {
	local := d.Metrics(now)
	result := observability.DatabaseSnapshot{
		Pool: local.Pool, OperationsOmitted: local.OperationsOmitted,
		Connections: make(map[string]observability.DatabaseConnectionSnapshot, len(local.Connections)),
	}
	for purpose, counts := range local.Connections {
		result.Connections[purpose] = observability.DatabaseConnectionSnapshot{
			Open: counts.Open, Connecting: counts.Connecting, Opened: counts.Opened,
			Closed: counts.Closed, Failed: counts.Failed,
		}
	}
	for _, operation := range local.ActiveOperations {
		result.ActiveOperations = append(result.ActiveOperations, observability.DatabaseOperationSnapshot(operation))
	}
	return result
}

// register this defer before transaction cleanup so the duration and outcome
// include rollback and any error it adds to the returned error.
func (d *Database) observeOperation(operation string, err *error) func() {
	if d == nil || d.activity == nil {
		return func() {}
	}
	metrics := d.activity.metrics.Load()
	if metrics == nil {
		return func() {}
	}
	started := time.Now()
	return func() { metrics.ObserveOperation(operation, *err, time.Since(started)) }
}
