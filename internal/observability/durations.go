package observability

import (
	"context"
	"time"
)

// DurationBucketsSeconds returns independent boundaries shared by operation,
// HTTP, SQL, and driver-observed guard histograms. the final implicit +Inf bucket
// also counts operations longer than two minutes.
func DurationBucketsSeconds() []float64 {
	return []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 60, 120}
}

func durationOutcome(err error) string {
	return ErrorOutcome(err).String()
}

// ObserveOperation records only the fixed application operations below. nil
// metrics are useful for callers that do not run a process metrics listener.
func (m *Metrics) ObserveOperation(operation string, err error, elapsed time.Duration) {
	m.ObserveOperationContext(context.Background(), operation, err, elapsed)
}

// ObserveOperationContext attaches a measured interval to the caller's span and
// metric exemplar context. use it instead of adding a second span at this boundary.
func (m *Metrics) ObserveOperationContext(ctx context.Context, operation string, err error, elapsed time.Duration) {
	if m == nil {
		return
	}
	var histogram *histogram
	switch operation {
	case "CreatePublishRun", "HeartbeatPublishRun", "ClosePublishRun", "ReadIngressRoutingTableSnapshot", "RefreshPortPoolMetrics",
		"AdvanceIngressRoutingRetention", "PruneIngressRoutingHistory",
		"ReadIngressRoutingTableEvents", "RenewIngress",
		"ClaimPublisherConnection", "MarkPublisherConnectionReady":
		histogram = m.controlOperations
	case "IngressRegister", "IngressFetchSnapshot", "IngressFetchEvents", "IngressRenewLease",
		"IngressApplySnapshot", "IngressApplyEvents",
		"IngressRelayConnect", "IngressForwardingStart", "IngressForwardingCleanup",
		"IngressBackendAttempt", "IngressBackendCleanup", "IngressFallback":
		histogram = m.ingressOperations
	case "RelayRegister", "RelayRenewLease", "RelayBeginDrain", "RelayDrain",
		"RelayAdmitPublisherConnection", "RelayOpenVisitorStream", "RelayDisconnectPublisherConnection":
		histogram = m.relayOperations
	default:
		return
	}
	name := operationName(operation) // the switch above is the closed operation boundary.
	ctx, finish := m.completedOperation(ctx, name, elapsed)
	histogram.With(Operation.Dimension(name), OutcomeKey.Dimension(ErrorOutcome(err))).ObserveContext(ctx, elapsed.Seconds())
	finish(err)
}

// ObserveDatabaseQuery accepts only names sanitized by the controlstate tracer:
// compiled sqlc operations, transaction commands, or the fixed "unknown" label.
func (m *Metrics) ObserveDatabaseQuery(operation DatabaseOperationName, err error, elapsed time.Duration) {
	if m == nil {
		return
	}
	outcome := durationOutcome(err)
	m.databaseQueryDuration.With(Operation.Dimension(operation.operation()), OutcomeKey.Dimension(ErrorOutcome(err))).Observe(elapsed.Seconds())
	m.completedSpan("database."+operation.operation(), outcome, elapsed)
	if err != nil {
		phase := operationName("query")
		switch operation.String() {
		case "begin", "commit", "rollback":
			phase = operation.operation()
		}
		m.databaseFailures.With(Operation.Dimension(phase), OutcomeKey.Dimension(ErrorOutcome(err))).Inc()
	}
}

func (m *Metrics) ObserveDatabaseAcquire(err error, elapsed time.Duration) {
	if m == nil {
		return
	}
	m.databaseAcquireDuration.With(OutcomeKey.Dimension(ErrorOutcome(err))).Observe(elapsed.Seconds())
	if err != nil {
		m.databaseFailures.With(Operation.Dimension("acquire"), OutcomeKey.Dimension(ErrorOutcome(err))).Inc()
	}
}

// ObserveDatabaseGuard records a driver-observed guard interval. outcome is the
// transaction-ending command's outcome, not the application operation's outcome.
func (m *Metrics) ObserveDatabaseGuard(operation DatabaseOperationName, err error, elapsed time.Duration) {
	if m != nil {
		m.databaseGuardDuration.With(Operation.Dimension(operation.operation()), OutcomeKey.Dimension(ErrorOutcome(err))).Observe(elapsed.Seconds())
	}
}
