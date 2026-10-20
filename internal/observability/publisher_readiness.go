package observability

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/metric"
)

type publisherReadinessMetrics struct {
	current, lastCheck, lastSuccess, targetHealthy, configurationCurrent metric.Float64Gauge
}

func (m *Metrics) initPublisherReadiness() {
	for _, item := range []struct {
		name, semantics string
		instrument      *metric.Float64Gauge
	}{
		{"tnl_publisher_ready", "Current publisher readiness decision; combine with last check and confirmed lease expiration for freshness.", &m.publisherReadinessMetrics.current},
		{"tnl_publisher_readiness_last_check_timestamp_seconds", "Most recent publisher readiness check, including unsuccessful checks.", &m.publisherReadinessMetrics.lastCheck},
		{"tnl_publisher_readiness_last_success_timestamp_seconds", "Most recent successful publisher readiness check; a failure never advances it.", &m.publisherReadinessMetrics.lastSuccess},
		{"tnl_publisher_target_healthy", "Latest target health decision; independent of publisher lease and configuration validity.", &m.publisherReadinessMetrics.targetHealthy},
		{"tnl_publisher_configuration_current", "Whether the latest control response matched the current run and approved configuration; target health is separate.", &m.publisherReadinessMetrics.configurationCurrent},
	} {
		describe(m.meter, item.name, item.semantics, "gauge", nil, string(Component), string(ServiceProtocol), string(AccessPath), string(Exposure))
		*item.instrument, _ = m.meter.Float64Gauge(item.name, metric.WithDescription(item.semantics))
	}
}

// PublisherReadinessStatus records a snapshot, not a lifecycle callback. the
// caller retains last success across failures and never extends a failed lease.
func PublisherReadinessStatus(ctx context.Context, ready, healthy, current bool, checked, succeeded time.Time) {
	m := FromContext(ctx)
	if m == nil {
		return
	}
	opts := metric.WithAttributes(publisherDataAttributes(ctx)...)
	value := func(b bool) float64 {
		if b {
			return 1
		}
		return 0
	}
	m.publisherReadinessMetrics.current.Record(ctx, value(ready), opts)
	m.publisherReadinessMetrics.lastCheck.Record(ctx, routingTimestamp(checked), opts)
	m.publisherReadinessMetrics.lastSuccess.Record(ctx, routingTimestamp(succeeded), opts)
	m.publisherReadinessMetrics.targetHealthy.Record(ctx, value(healthy), opts)
	m.publisherReadinessMetrics.configurationCurrent.Record(ctx, value(current), opts)
	PublisherReadiness(ctx, ready)
}
