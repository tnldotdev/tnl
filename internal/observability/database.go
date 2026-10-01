package observability

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// DatabaseSnapshot is process-local database state collected without I/O.
type DatabaseSnapshot struct {
	Pool              *pgxpool.Stat
	Connections       map[string]DatabaseConnectionSnapshot
	ActiveOperations  []DatabaseOperationSnapshot
	OperationsOmitted int
}

type DatabaseConnectionSnapshot struct {
	Open       int64
	Connecting int64
	Opened     int64
	Closed     int64
	Failed     int64
}

type DatabaseOperationSnapshot struct {
	Operation      string
	ElapsedSeconds float64
}

// RegisterDatabase exposes in-memory database state. its source must never
// acquire a connection because collection must remain available under database
// contention and pool exhaustion.
func (m *Metrics) RegisterDatabase(source func(time.Time) DatabaseSnapshot) {
	m.registry.MustRegister(newDatabaseCollector(source))
}

type databaseCollector struct {
	source func(time.Time) DatabaseSnapshot

	poolMaxConnections      *prometheus.Desc
	poolAcquiredConnections *prometheus.Desc
	poolIdleConnections     *prometheus.Desc
	poolTotalConnections    *prometheus.Desc
	poolAcquires            *prometheus.Desc
	poolWaitedAcquires      *prometheus.Desc
	poolAcquireWaitSeconds  *prometheus.Desc
	poolCanceledAcquires    *prometheus.Desc
	clientConnections       *prometheus.Desc
	clientConnectionEvents  *prometheus.Desc
	operationsActive        *prometheus.Desc
	operationOldestAge      *prometheus.Desc
	operationsOmitted       *prometheus.Desc
}

func newDatabaseCollector(source func(time.Time) DatabaseSnapshot) *databaseCollector {
	return &databaseCollector{
		source: source,
		poolMaxConnections: prometheus.NewDesc(
			"tnl_database_pool_max_connections", "Configured connection limit.", nil, nil,
		),
		poolAcquiredConnections: prometheus.NewDesc(
			"tnl_database_pool_acquired_connections", "Connections currently in use.", nil, nil,
		),
		poolIdleConnections: prometheus.NewDesc(
			"tnl_database_pool_idle_connections", "Connections available for acquisition.", nil, nil,
		),
		poolTotalConnections: prometheus.NewDesc(
			"tnl_database_pool_total_connections", "Total pool connections, including those being constructed.", nil, nil,
		),
		poolAcquires: prometheus.NewDesc(
			"tnl_database_pool_acquires_total", "Successful connection acquisitions.", nil, nil,
		),
		poolWaitedAcquires: prometheus.NewDesc(
			"tnl_database_pool_waited_acquires_total", "Successful acquisitions that waited for an available connection.", nil, nil,
		),
		poolAcquireWaitSeconds: prometheus.NewDesc(
			"tnl_database_pool_acquire_wait_seconds_total", "Time spent waiting on successful acquisitions from an empty pool.", nil, nil,
		),
		poolCanceledAcquires: prometheus.NewDesc(
			"tnl_database_pool_canceled_acquires_total", "Connection acquisitions canceled before completion.", nil, nil,
		),
		clientConnections: prometheus.NewDesc(
			"tnl_database_client_connections", "Current local database client sockets by purpose and state.", []string{"purpose", "state"}, nil,
		),
		clientConnectionEvents: prometheus.NewDesc(
			"tnl_database_client_connection_events_total", "Local database client connection lifecycle events.", []string{"purpose", "event"}, nil,
		),
		operationsActive: prometheus.NewDesc(
			"tnl_database_operations_active", "Current active request-pool operations by compiled operation name.", []string{"operation"}, nil,
		),
		operationOldestAge: prometheus.NewDesc(
			"tnl_database_operation_oldest_age_seconds", "Age of the oldest active request-pool operation by compiled operation name.", []string{"operation"}, nil,
		),
		operationsOmitted: prometheus.NewDesc(
			"tnl_database_operations_omitted", "Current active request-pool operations omitted by the bounded tracker.", nil, nil,
		),
	}
}

func (c *databaseCollector) Describe(descriptions chan<- *prometheus.Desc) {
	for _, description := range []*prometheus.Desc{
		c.poolMaxConnections, c.poolAcquiredConnections, c.poolIdleConnections, c.poolTotalConnections,
		c.poolAcquires, c.poolWaitedAcquires, c.poolAcquireWaitSeconds, c.poolCanceledAcquires,
		c.clientConnections, c.clientConnectionEvents, c.operationsActive, c.operationOldestAge, c.operationsOmitted,
	} {
		descriptions <- description
	}
}

func (c *databaseCollector) Collect(metrics chan<- prometheus.Metric) {
	snapshot := c.source(time.Now())
	if pool := snapshot.Pool; pool != nil {
		metrics <- prometheus.MustNewConstMetric(c.poolMaxConnections, prometheus.GaugeValue, float64(pool.MaxConns()))
		metrics <- prometheus.MustNewConstMetric(c.poolAcquiredConnections, prometheus.GaugeValue, float64(pool.AcquiredConns()))
		metrics <- prometheus.MustNewConstMetric(c.poolIdleConnections, prometheus.GaugeValue, float64(pool.IdleConns()))
		metrics <- prometheus.MustNewConstMetric(c.poolTotalConnections, prometheus.GaugeValue, float64(pool.TotalConns()))
		metrics <- prometheus.MustNewConstMetric(c.poolAcquires, prometheus.CounterValue, float64(pool.AcquireCount()))
		metrics <- prometheus.MustNewConstMetric(c.poolWaitedAcquires, prometheus.CounterValue, float64(pool.EmptyAcquireCount()))
		metrics <- prometheus.MustNewConstMetric(c.poolAcquireWaitSeconds, prometheus.CounterValue, pool.EmptyAcquireWaitTime().Seconds())
		metrics <- prometheus.MustNewConstMetric(c.poolCanceledAcquires, prometheus.CounterValue, float64(pool.CanceledAcquireCount()))
	}
	for purpose, counts := range snapshot.Connections {
		metrics <- prometheus.MustNewConstMetric(c.clientConnections, prometheus.GaugeValue, float64(counts.Open), purpose, "open")
		metrics <- prometheus.MustNewConstMetric(c.clientConnections, prometheus.GaugeValue, float64(counts.Connecting), purpose, "connecting")
		metrics <- prometheus.MustNewConstMetric(c.clientConnectionEvents, prometheus.CounterValue, float64(counts.Opened), purpose, "opened")
		metrics <- prometheus.MustNewConstMetric(c.clientConnectionEvents, prometheus.CounterValue, float64(counts.Closed), purpose, "closed")
		metrics <- prometheus.MustNewConstMetric(c.clientConnectionEvents, prometheus.CounterValue, float64(counts.Failed), purpose, "failed")
	}
	type operationAggregate struct {
		count  int
		oldest float64
	}
	operations := make(map[string]operationAggregate)
	for _, operation := range snapshot.ActiveOperations {
		aggregate := operations[operation.Operation]
		aggregate.count++
		aggregate.oldest = max(aggregate.oldest, operation.ElapsedSeconds)
		operations[operation.Operation] = aggregate
	}
	for operation, aggregate := range operations {
		metrics <- prometheus.MustNewConstMetric(c.operationsActive, prometheus.GaugeValue, float64(aggregate.count), operation)
		metrics <- prometheus.MustNewConstMetric(c.operationOldestAge, prometheus.GaugeValue, aggregate.oldest, operation)
	}
	metrics <- prometheus.MustNewConstMetric(c.operationsOmitted, prometheus.GaugeValue, float64(snapshot.OperationsOmitted))
}
