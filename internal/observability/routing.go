package observability

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/metric"
)

// IngressRoutingSnapshot is bounded, process-local controller state. revisions
// describe successful routing responses, not control's current revision while
// a request is pending. CaughtUp requires an event response confirming catch-up;
// applying the initial snapshot alone only establishes Initialized.
type IngressRoutingSnapshot struct {
	Initialized          bool
	CaughtUp             bool
	LastSuccessfulCheck  time.Time
	LastCaughtUp         time.Time
	LastAcknowledged     time.Time
	LatestRevision       int64
	AppliedRevision      int64
	AcknowledgedRevision int64
	UpdateFailures       uint64
	Resnapshots          uint64
}

// RegisterIngressRouting exposes one ingress controller's in-memory state. the
// source must perform no network or database I/O, including during a stalled poll.
func (m *Metrics) RegisterIngressRouting(source func() IngressRoutingSnapshot) {
	var instruments []metric.Observable
	var gauges []metric.Float64ObservableGauge
	var counters []metric.Float64ObservableCounter
	for i, spec := range [][2]string{
		{"initialized", "Whether a routing snapshot has been applied; independent of lease readiness."},
		{"caught_up", "Whether the last successful event response confirmed catch-up, cleared on update failure or resnapshot; not a guarantee about pending updates."},
		{"last_successful_check_timestamp_seconds", "Unix time of the last successfully applied snapshot or event response, including empty responses; zero before success."},
		{"last_caught_up_timestamp_seconds", "Unix time of the last event response confirming catch-up; zero before confirmation."},
		{"latest_observed_revision", "Highest control revision observed in a successfully applied routing response; pending requests may hide newer revisions."},
		{"applied_revision", "Last applied routing-table revision."},
		{"acknowledged_revision", "Last routing-table revision acknowledged by a successful ingress lease renewal."},
		{"last_acknowledged_timestamp_seconds", "Unix time of the last routing-table acknowledgment; zero before success."},
		{"update_failures_total", "Routing fetch or apply failures, excluding resnapshot-required responses and controller shutdown cancellation."},
		{"resnapshots_total", "Resnapshot-required responses received from routing event requests."},
	} {
		if i < 8 {
			describe(m.meter, "tnl_ingress_routing_"+spec[0], spec[1], "gauge", nil)
			g, err := m.meter.Float64ObservableGauge("tnl_ingress_routing_"+spec[0], metric.WithDescription(spec[1]))
			if err != nil {
				panic(err)
			}
			gauges = append(gauges, g)
			instruments = append(instruments, g)
		} else {
			describe(m.meter, "tnl_ingress_routing_"+spec[0], spec[1], "counter", nil)
			c, err := m.meter.Float64ObservableCounter("tnl_ingress_routing_"+spec[0], metric.WithDescription(spec[1]))
			if err != nil {
				panic(err)
			}
			counters = append(counters, c)
			instruments = append(instruments, c)
		}
	}
	_, err := m.meter.RegisterCallback(func(_ context.Context, observer metric.Observer) error {
		snapshot := source()
		var initialized, caughtUp float64
		if snapshot.Initialized {
			initialized = 1
		}
		if snapshot.CaughtUp {
			caughtUp = 1
		}
		for i, value := range []float64{
			initialized, caughtUp,
			routingTimestamp(snapshot.LastSuccessfulCheck), routingTimestamp(snapshot.LastCaughtUp),
			float64(snapshot.LatestRevision), float64(snapshot.AppliedRevision),
			float64(snapshot.AcknowledgedRevision), routingTimestamp(snapshot.LastAcknowledged),
		} {
			observer.ObserveFloat64(gauges[i], value)
		}
		observer.ObserveFloat64(counters[0], float64(snapshot.UpdateFailures))
		observer.ObserveFloat64(counters[1], float64(snapshot.Resnapshots))
		return nil
	}, instruments...)
	if err != nil {
		panic(err)
	}
}

func routingTimestamp(at time.Time) float64 {
	if at.IsZero() {
		return 0
	}
	return float64(at.Unix()) + float64(at.Nanosecond())/float64(time.Second)
}
