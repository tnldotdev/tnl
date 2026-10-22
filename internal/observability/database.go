package observability

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/metric"
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
	Operation      DatabaseOperationName
	ElapsedSeconds float64
}

// RegisterDatabase exposes in-memory database state. its source must never
// acquire a connection because collection must remain available under database
// contention and pool exhaustion.
func (m *Metrics) RegisterDatabase(source func(time.Time) DatabaseSnapshot) {
	var instruments []metric.Observable
	gauge := func(name, help string) metric.Float64ObservableGauge {
		describe(m.meter, "tnl_database_"+name, help, KindGauge, nil, databaseKeys(name)...)
		g, err := m.meter.Float64ObservableGauge("tnl_database_"+name, metric.WithDescription(help))
		if err != nil {
			panic(err)
		}
		instruments = append(instruments, g)
		return g
	}
	counter := func(name, help string) metric.Float64ObservableCounter {
		describe(m.meter, "tnl_database_"+name, help, KindCounter, nil, databaseKeys(name)...)
		c, err := m.meter.Float64ObservableCounter("tnl_database_"+name, metric.WithDescription(help))
		if err != nil {
			panic(err)
		}
		instruments = append(instruments, c)
		return c
	}
	poolMax := gauge("pool_max_connections", "Configured connection limit.")
	poolAcquired := gauge("pool_acquired_connections", "Connections currently in use.")
	poolIdle := gauge("pool_idle_connections", "Connections available for acquisition.")
	poolTotal := gauge("pool_total_connections", "Total pool connections, including those being constructed.")
	poolAcquires := counter("pool_acquires_total", "Successful connection acquisitions.")
	poolWaited := counter("pool_waited_acquires_total", "Successful acquisitions that waited for an available connection.")
	poolWaitSeconds := counter("pool_acquire_wait_seconds_total", "Time spent waiting on successful acquisitions from an empty pool.")
	poolCanceled := counter("pool_canceled_acquires_total", "Connection acquisitions canceled before completion.")
	connections := gauge("client_connections", "Current local database client sockets by purpose and state.")
	connectionEvents := counter("client_connection_events_total", "Local database client connection lifecycle events.")
	active := gauge("operations_active", "Current active request-pool operations by compiled operation name.")
	oldest := gauge("operation_oldest_age_seconds", "Age of the oldest active request-pool operation by compiled operation name.")
	omitted := gauge("operations_omitted", "Current active request-pool operations omitted by the bounded tracker.")
	_, err := m.meter.RegisterCallback(func(_ context.Context, observer metric.Observer) error {
		snapshot := source(time.Now())
		if pool := snapshot.Pool; pool != nil {
			observer.ObserveFloat64(poolMax, float64(pool.MaxConns()))
			observer.ObserveFloat64(poolAcquired, float64(pool.AcquiredConns()))
			observer.ObserveFloat64(poolIdle, float64(pool.IdleConns()))
			observer.ObserveFloat64(poolTotal, float64(pool.TotalConns()))
			observer.ObserveFloat64(poolAcquires, float64(pool.AcquireCount()))
			observer.ObserveFloat64(poolWaited, float64(pool.EmptyAcquireCount()))
			observer.ObserveFloat64(poolWaitSeconds, pool.EmptyAcquireWaitTime().Seconds())
			observer.ObserveFloat64(poolCanceled, float64(pool.CanceledAcquireCount()))
		}
		for purpose, counts := range snapshot.Connections {
			observer.ObserveFloat64(connections, float64(counts.Open), metric.WithAttributes(databasePurpose.String(purpose), State.Value(StateOpen)))
			observer.ObserveFloat64(connections, float64(counts.Connecting), metric.WithAttributes(databasePurpose.String(purpose), State.Value(StateConnecting)))
			for event, count := range map[string]int64{"opened": counts.Opened, "closed": counts.Closed, "failed": counts.Failed} {
				parsed, _ := ParseEvent(event)
				observer.ObserveFloat64(connectionEvents, float64(count), metric.WithAttributes(databasePurpose.String(purpose), Event.Value(parsed)))
			}
		}
		type operationAggregate struct {
			count  int
			oldest float64
		}
		operations := make(map[DatabaseOperationName]operationAggregate)
		for _, operation := range snapshot.ActiveOperations {
			aggregate := operations[operation.Operation]
			aggregate.count++
			aggregate.oldest = max(aggregate.oldest, operation.ElapsedSeconds)
			operations[operation.Operation] = aggregate
		}
		for operation, aggregate := range operations {
			attrs := metric.WithAttributes(Operation.Value(operation.operation()))
			observer.ObserveFloat64(active, float64(aggregate.count), attrs)
			observer.ObserveFloat64(oldest, aggregate.oldest, attrs)
		}
		observer.ObserveFloat64(omitted, float64(snapshot.OperationsOmitted))
		return nil
	}, instruments...)
	if err != nil {
		panic(err)
	}
}

func databaseKeys(name string) []MetricKey {
	switch name {
	case "client_connections":
		return []MetricKey{databasePurpose, State}
	case "client_connection_events_total":
		return []MetricKey{databasePurpose, Event}
	case "operations_active", "operation_oldest_age_seconds":
		return []MetricKey{Operation}
	}
	return nil
}
