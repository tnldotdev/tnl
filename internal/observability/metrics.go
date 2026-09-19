package observability

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics owns a process-local Prometheus registry.
type Metrics struct {
	registry             *prometheus.Registry
	routes               *prometheus.GaugeVec
	relayLeases          *prometheus.GaugeVec
	publisherConnections *prometheus.GaugeVec
	streams              prometheus.Gauge
	capacityRejections   *prometheus.CounterVec
	sourceLimiterRejects prometheus.Counter
	sourceLimiterEntries prometheus.Gauge
	ipAllowlistDenials   prometheus.Counter
	forwardedBytes       *prometheus.CounterVec
	controlRequests      *prometheus.CounterVec
	controlDuration      *prometheus.HistogramVec
	controlInFlight      *prometheus.GaugeVec
}

// New constructs an isolated registry for one tnld role.
func New(role string) *Metrics {
	registry := prometheus.NewRegistry()
	info := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tnl_info", Help: "Information about the running tnld process.", ConstLabels: prometheus.Labels{"role": role},
	})
	info.Set(1)
	metrics := &Metrics{
		registry: registry,
		routes: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tnl_routes", Help: "Current routes by lifecycle state.",
		}, []string{"state"}),
		relayLeases: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tnl_relay_leases", Help: "Current relay leases by state.",
		}, []string{"state"}),
		publisherConnections: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tnl_publisher_connections", Help: "Current publisher connections by state.",
		}, []string{"state"}),
		streams: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tnl_streams_active", Help: "Current active visitor streams.",
		}),
		capacityRejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_capacity_rejections_total", Help: "Operations rejected because a bounded resource was full.",
		}, []string{"resource"}),
		sourceLimiterRejects: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tnl_source_limiter_rejections_total", Help: "Ingress starts rejected by per-source limiting.",
		}),
		sourceLimiterEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tnl_source_limiter_entries", Help: "Current bounded per-source limiter entries.",
		}),
		ipAllowlistDenials: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tnl_ip_allowlist_denials_total", Help: "Ingress connections denied by route IP policy.",
		}),
		forwardedBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_forwarded_bytes_total", Help: "Bytes forwarded through route ingress.",
		}, []string{"direction"}),
		controlRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_control_requests_total", Help: "Control API requests by operation and outcome.",
		}, []string{"operation", "outcome"}),
		controlDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tnl_control_request_duration_seconds", Help: "Control API request duration by operation.",
		}, []string{"operation"}),
		controlInFlight: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tnl_control_requests_in_flight", Help: "Control API requests currently executing by operation.",
		}, []string{"operation"}),
	}
	registry.MustRegister(
		info, metrics.routes, metrics.relayLeases, metrics.publisherConnections, metrics.streams,
		metrics.capacityRejections, metrics.sourceLimiterRejects, metrics.sourceLimiterEntries,
		metrics.ipAllowlistDenials, metrics.forwardedBytes, metrics.controlRequests, metrics.controlDuration, metrics.controlInFlight,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return metrics
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *Metrics) SetRoutes(state string, count int) {
	m.routes.WithLabelValues(state).Set(float64(count))
}

func (m *Metrics) SetRelayLeases(state string, count int) {
	m.relayLeases.WithLabelValues(state).Set(float64(count))
}

func (m *Metrics) AddRelayLeases(state string, delta int) {
	m.relayLeases.WithLabelValues(state).Add(float64(delta))
}

func (m *Metrics) SetPublisherConnections(state string, count int) {
	m.publisherConnections.WithLabelValues(state).Set(float64(count))
}

func (m *Metrics) AddPublisherConnections(state string, delta int) {
	m.publisherConnections.WithLabelValues(state).Add(float64(delta))
}

func (m *Metrics) SetStreams(count int) { m.streams.Set(float64(count)) }

func (m *Metrics) IncCapacityRejection(resource string) {
	m.capacityRejections.WithLabelValues(resource).Inc()
}

func (m *Metrics) IncSourceLimiterRejection() { m.sourceLimiterRejects.Inc() }

func (m *Metrics) SetSourceLimiterEntries(count int) { m.sourceLimiterEntries.Set(float64(count)) }

func (m *Metrics) IncIPAllowlistDenial() { m.ipAllowlistDenials.Inc() }

func (m *Metrics) AddForwardedBytes(direction string, count int64) {
	m.forwardedBytes.WithLabelValues(direction).Add(float64(count))
}

func (m *Metrics) ObserveControlRequest(operation, outcome string, duration time.Duration) {
	m.controlRequests.WithLabelValues(operation, outcome).Inc()
	m.controlDuration.WithLabelValues(operation).Observe(duration.Seconds())
}
