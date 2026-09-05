package observability

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// IngressRoutingSnapshot is bounded, process-local controller state. Revisions
// describe successful routing responses, not control's current revision while
// a request is pending. CaughtUp requires an event response confirming catch-up;
// applying the initial snapshot alone only establishes Initialized.
type IngressRoutingSnapshot struct {
	Initialized         bool
	CaughtUp            bool
	LastSuccessfulCheck time.Time
	LastCaughtUp        time.Time
	LatestRevision      int64
	AppliedRevision     int64
	UpdateFailures      uint64
	Resnapshots         uint64
}

// RegisterIngressRouting exposes one ingress controller's in-memory state. The
// source must perform no network or database I/O, including during a stalled poll.
func (m *Metrics) RegisterIngressRouting(source func() IngressRoutingSnapshot) {
	m.registry.MustRegister(newIngressRoutingCollector(source))
}

type ingressRoutingCollector struct {
	source func() IngressRoutingSnapshot
	descs  [9]*prometheus.Desc
}

func newIngressRoutingCollector(source func() IngressRoutingSnapshot) *ingressRoutingCollector {
	c := &ingressRoutingCollector{source: source}
	for i, metric := range [][2]string{
		{"initialized", "Whether a routing snapshot has been applied; independent of lease readiness."},
		{"caught_up", "Whether the last successful event response confirmed catch-up, cleared on update failure or resnapshot; not a guarantee about pending updates."},
		{"last_successful_check_timestamp_seconds", "Unix time of the last successfully applied snapshot or event response, including empty responses; zero before success."},
		{"last_caught_up_timestamp_seconds", "Unix time of the last event response confirming catch-up; zero before confirmation."},
		{"latest_observed_revision", "Highest control revision observed in a successfully applied routing response; pending requests may hide newer revisions."},
		{"applied_revision", "Last applied routing-table revision."},
		{"known_revision_backlog", "Latest observed minus applied revision; zero does not imply freshness while a request is pending."},
		{"update_failures_total", "Routing fetch or apply failures, excluding resnapshot-required responses and controller shutdown cancellation."},
		{"resnapshots_total", "Resnapshot-required responses received from routing event requests."},
	} {
		c.descs[i] = prometheus.NewDesc("tnl_ingress_routing_"+metric[0], metric[1], nil, nil)
	}
	return c
}

func (c *ingressRoutingCollector) Describe(descs chan<- *prometheus.Desc) {
	for _, desc := range c.descs {
		descs <- desc
	}
}

func (c *ingressRoutingCollector) Collect(metrics chan<- prometheus.Metric) {
	snapshot := c.source()
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
		float64(max(0, snapshot.LatestRevision-snapshot.AppliedRevision)),
	} {
		metrics <- prometheus.MustNewConstMetric(c.descs[i], prometheus.GaugeValue, value)
	}
	metrics <- prometheus.MustNewConstMetric(c.descs[7], prometheus.CounterValue, float64(snapshot.UpdateFailures))
	metrics <- prometheus.MustNewConstMetric(c.descs[8], prometheus.CounterValue, float64(snapshot.Resnapshots))
}

func routingTimestamp(at time.Time) float64 {
	if at.IsZero() {
		return 0
	}
	return float64(at.Unix()) + float64(at.Nanosecond())/float64(time.Second)
}
