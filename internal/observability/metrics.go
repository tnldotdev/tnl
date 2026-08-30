package observability

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics owns a process-local Prometheus registry.
type Metrics struct {
	registry           *prometheus.Registry
	routes             *prometheus.GaugeVec
	workerRoutes       prometheus.Gauge
	workerCapacity     prometheus.Gauge
	workerDraining     prometheus.Gauge
	streams            prometheus.Gauge
	tailcatPaths       *prometheus.GaugeVec
	tailcatFailures    *prometheus.CounterVec
	tailcatForcedClose prometheus.Counter
	capacityRejections *prometheus.CounterVec
	forwardedBytes     *prometheus.CounterVec
}

// New constructs an isolated registry for one process role.
func New(mode string) *Metrics {
	registry := prometheus.NewRegistry()
	info := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "tnl_info",
		Help:        "Information about the running TNL process.",
		ConstLabels: prometheus.Labels{"mode": mode},
	})
	info.Set(1)
	metrics := &Metrics{
		registry: registry,
		routes: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tnl_routes",
			Help: "Current routes by lifecycle state.",
		}, []string{"state"}),
		workerRoutes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tnl_worker_routes_active",
			Help: "Current active routes owned by this worker.",
		}),
		workerCapacity: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tnl_worker_route_capacity",
			Help: "Maximum routes accepted by this worker.",
		}),
		workerDraining: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tnl_worker_draining",
			Help: "Whether this worker is draining and refusing new routes.",
		}),
		streams: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tnl_streams_active",
			Help: "Current active application streams.",
		}),
		tailcatPaths: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tnl_tailcat_paths",
			Help: "Current Tailcat routes by direct or DERP path.",
		}, []string{"path"}),
		tailcatFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_tailcat_failures_total",
			Help: "Tailcat operation failures by stable operation and reason.",
		}, []string{"operation", "reason"}),
		tailcatForcedClose: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tnl_tailcat_forced_closes_total",
			Help: "Tailcat routes force-closed after their drain deadline.",
		}),
		capacityRejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_capacity_rejections_total",
			Help: "Operations rejected because a bounded resource was full.",
		}, []string{"resource"}),
		forwardedBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_forwarded_bytes_total",
			Help: "Bytes forwarded by direction.",
		}, []string{"direction"}),
	}
	registry.MustRegister(
		info,
		metrics.routes,
		metrics.workerRoutes,
		metrics.workerCapacity,
		metrics.workerDraining,
		metrics.streams,
		metrics.tailcatPaths,
		metrics.tailcatFailures,
		metrics.tailcatForcedClose,
		metrics.capacityRejections,
		metrics.forwardedBytes,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return metrics
}

// Handler returns the Prometheus scrape handler for this registry.
func (m *Metrics) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))
	return mux
}

// SetRoutes records the authoritative route count for a lifecycle state.
func (m *Metrics) SetRoutes(state string, count int) {
	m.routes.WithLabelValues(state).Set(float64(count))
}

// SetWorkerRoutes records routes currently owned by this worker.
func (m *Metrics) SetWorkerRoutes(count int) {
	m.workerRoutes.Set(float64(count))
}

// SetWorkerCapacity records this worker's hard route limit.
func (m *Metrics) SetWorkerCapacity(count int) {
	m.workerCapacity.Set(float64(count))
}

// SetWorkerDraining records whether the worker is refusing new routes.
func (m *Metrics) SetWorkerDraining(draining bool) {
	value := 0
	if draining {
		value = 1
	}
	m.workerDraining.Set(float64(value))
}

// SetStreams records the number of active application streams.
func (m *Metrics) SetStreams(count int) {
	m.streams.Set(float64(count))
}

// SetTailcatPaths records the current count for a bounded path class.
func (m *Metrics) SetTailcatPaths(path string, count int) {
	m.tailcatPaths.WithLabelValues(path).Set(float64(count))
}

// IncTailcatFailure records one Tailcat failure using stable classes.
func (m *Metrics) IncTailcatFailure(operation, reason string) {
	m.tailcatFailures.WithLabelValues(operation, reason).Inc()
}

// AddTailcatForcedCloses records routes that exceeded their drain deadline.
func (m *Metrics) AddTailcatForcedCloses(count int) {
	m.tailcatForcedClose.Add(float64(count))
}

// IncCapacityRejection records one bounded-resource rejection.
func (m *Metrics) IncCapacityRejection(resource string) {
	m.capacityRejections.WithLabelValues(resource).Inc()
}

// AddForwardedBytes records bytes forwarded in a stable direction.
func (m *Metrics) AddForwardedBytes(direction string, count int64) {
	m.forwardedBytes.WithLabelValues(direction).Add(float64(count))
}
