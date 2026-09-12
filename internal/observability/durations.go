package observability

import (
	"context"
	"errors"
	"time"
)

// DurationBucketsSeconds returns independent boundaries shared by operation,
// HTTP, SQL, and driver-observed guard histograms. The final implicit +Inf bucket
// also counts operations longer than two minutes.
func DurationBucketsSeconds() []float64 {
	return []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 60, 120}
}

func durationOutcome(err error) string {
	switch {
	case err == nil:
		return "success"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "error"
	}
}

// ObserveOperation records only the fixed application operations below. Nil
// metrics are useful for callers that do not run a process metrics listener.
func (m *Metrics) ObserveOperation(operation string, err error, elapsed time.Duration) {
	if m == nil {
		return
	}
	switch operation {
	case "CreateRouteSession", "HeartbeatRouteSession", "CloseRouteSession", "ReadIngressRoutingTableSnapshot",
		"AdvanceIngressRoutingRetention", "PruneIngressRoutingHistory",
		"ReadIngressRoutingTableEvents", "ReportIngressUsage", "RenewIngress",
		"ClaimPublisherConnection", "MarkPublisherConnectionReady",
		"IngressFetchSnapshot", "IngressFetchEvents", "IngressRenewLease",
		"IngressApplySnapshot", "IngressApplyEvents",
		"RelayRegister", "RelayRenewLease", "RelayBeginDrain", "RelayDrain",
		"RelayAdmitPublisherConnection", "RelayOpenVisitorStream":
		m.operationDuration.WithLabelValues(operation, durationOutcome(err)).Observe(elapsed.Seconds())
	}
}

// ObserveDatabaseQuery accepts only names sanitized by the controlstate tracer:
// compiled sqlc operations, transaction commands, or the fixed "unknown" label.
func (m *Metrics) ObserveDatabaseQuery(operation string, err error, elapsed time.Duration) {
	if m != nil {
		m.databaseQueryDuration.WithLabelValues(operation, durationOutcome(err)).Observe(elapsed.Seconds())
	}
}

// ObserveDatabaseGuard records a driver-observed guard interval. Outcome is the
// transaction-ending command's outcome, not the application operation's outcome.
func (m *Metrics) ObserveDatabaseGuard(operation string, err error, elapsed time.Duration) {
	if m != nil {
		m.databaseGuardDuration.WithLabelValues(operation, durationOutcome(err)).Observe(elapsed.Seconds())
	}
}
