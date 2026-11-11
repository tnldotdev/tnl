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

// ObserveOperationContext attaches a measured interval to the caller's span and
// metric exemplar context. use it instead of adding a second span at this boundary.
func (m *Metrics) ObserveOperationContext(ctx context.Context, operation ServerOperation, err error, elapsed time.Duration) {
	if m == nil {
		return
	}
	var histogram *histogram
	switch operation {
	case OpCreatePublishRun, OpHeartbeatPublishRun, OpClosePublishRun, OpReadIngressRoutingTableSnapshot, OpRefreshPortPoolMetrics,
		OpAdvanceIngressRoutingRetention, OpPruneIngressRoutingHistory,
		OpReadIngressRoutingTableEvents, OpRenewIngress,
		OpClaimPublisherConnection, OpMarkPublisherConnectionReady:
		histogram = m.controlOperations
	case OpIngressRegister, OpIngressFetchSnapshot, OpIngressFetchEvents, OpIngressRenewLease,
		OpIngressApplySnapshot, OpIngressApplyEvents,
		OpIngressRelayConnect, OpIngressForwardingAck, OpIngressForwardingCleanup,
		OpIngressBackendAttempt, OpIngressBackendCleanup, OpIngressFallback:
		histogram = m.ingressOperations
	case OpRelayRegister, OpRelayRenewLease, OpRelayBeginDrain, OpRelayDrain,
		OpRelayAdmitPublisherConnection, OpRelayOpenVisitorStream, OpRelayDisconnectPublisherConnection:
		histogram = m.relayOperations
	default:
		return
	}
	name := operation.operation()
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
	outcome := semanticResult{outcome: ErrorOutcome(err)}
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
