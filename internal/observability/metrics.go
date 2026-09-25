package observability

import (
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

// Metrics owns a process-local Prometheus registry.
type Metrics struct {
	registry              *prometheus.Registry
	relayLeases           *prometheus.GaugeVec
	publisherConnections  *prometheus.GaugeVec
	streams               *prometheus.GaugeVec
	capacityRejections    *prometheus.CounterVec
	inspectionFailures    *prometheus.CounterVec
	challengeRejections   *prometheus.CounterVec
	sourceLimiterRejects  prometheus.Counter
	sourceLimiterEntries  prometheus.Gauge
	ipAllowlistDenials    prometheus.Counter
	forwardedBytes        *prometheus.CounterVec
	relayAttempts         *prometheus.CounterVec
	controlRequests       *prometheus.CounterVec
	controlDuration       *prometheus.HistogramVec
	controlInFlight       *prometheus.GaugeVec
	readinessAttempts     *prometheus.CounterVec
	readinessDuration     *prometheus.HistogramVec
	readinessAge          *prometheus.HistogramVec
	certificateWork       *prometheus.CounterVec
	certificateDuration   *prometheus.HistogramVec
	operationDuration     *prometheus.HistogramVec
	databaseQueryDuration *prometheus.HistogramVec
	databaseGuardDuration *prometheus.HistogramVec
	routingHistoryFloor   atomic.Uint64
	routingHistoryRows    *prometheus.CounterVec
	routingHistorySkipped prometheus.Counter
}

// New constructs an isolated registry for one tnld role.
func New(role string) *Metrics {
	registry := prometheus.NewRegistry()
	info := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tnl_info", Help: "Information about the running tnld process.", ConstLabels: prometheus.Labels{"role": role},
	})
	info.Set(1)
	metrics := &Metrics{
		registry:              registry,
		routingHistoryRows:    prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_routing_history_cleanup_rows_total", Help: "Committed routing-history cleanup rows by action."}, []string{"action"}),
		routingHistorySkipped: prometheus.NewCounter(prometheus.CounterOpts{Name: "tnl_routing_history_cleanup_skipped_total", Help: "Cleanup batches skipped because another control holds the cleanup guard."}),
		relayLeases: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tnl_relay_leases", Help: "Current relay leases by state.",
		}, []string{"state"}),
		publisherConnections: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tnl_publisher_connections", Help: "Current publisher connections by state.",
		}, []string{"state"}),
		streams: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tnl_streams_active", Help: "Current active visitor streams.",
		}, []string{"stage"}),
		capacityRejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_capacity_rejections_total", Help: "Operations rejected because a bounded resource was full.",
		}, []string{"resource"}),
		inspectionFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_ingress_inspection_failures_total", Help: "Ingress connections rejected before classification by fixed failure stage.",
		}, []string{"stage"}),
		challengeRejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_ingress_challenge_rejections_total", Help: "ACME TLS-ALPN connections rejected before relay forwarding by fixed reason.",
		}, []string{"reason"}),
		sourceLimiterRejects: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tnl_source_limiter_rejections_total", Help: "Ordinary visitor starts rejected by per-source limiting.",
		}),
		sourceLimiterEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tnl_source_limiter_entries", Help: "Current bounded ordinary visitor source limiter entries.",
		}),
		ipAllowlistDenials: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tnl_ip_allowlist_denials_total", Help: "Ingress connections denied by route IP policy.",
		}),
		forwardedBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_forwarded_bytes_total", Help: "Bytes forwarded through route ingress.",
		}, []string{"direction"}),
		relayAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_ingress_relay_attempts_total", Help: "Ingress internal-forwarding attempts by connection slot and bounded outcome.",
		}, []string{"connection_slot", "outcome"}),
		controlRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_control_requests_total", Help: "Control API requests by operation and outcome.",
		}, []string{"operation", "outcome"}),
		controlDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tnl_control_request_duration_seconds", Help: "Control API HTTP handler duration by operation and outcome, including long-poll waits.", Buckets: DurationBucketsSeconds(),
		}, []string{"operation", "outcome"}),
		controlInFlight: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tnl_control_requests_in_flight", Help: "Control API requests currently executing by operation.",
		}, []string{"operation"}),
		readinessAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_route_session_readiness_total", Help: "Route session readiness attempts by fixed outcome.",
		}, []string{"outcome"}),
		readinessDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tnl_route_session_readiness_duration_seconds", Help: "Time spent checking and publishing route session readiness.", Buckets: DurationBucketsSeconds(),
		}, []string{"outcome"}),
		readinessAge: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tnl_route_session_readiness_age_seconds", Help: "Age of the route session at a readiness decision; excludes other errors.",
			Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600},
		}, []string{"outcome"}),
		certificateWork: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_route_certificate_work_total", Help: "Route certificate worker iterations by fixed stage and outcome.",
		}, []string{"stage", "outcome"}),
		certificateDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tnl_route_certificate_work_duration_seconds", Help: "Route certificate worker iteration duration by fixed stage and outcome.", Buckets: DurationBucketsSeconds(),
		}, []string{"stage", "outcome"}),
		operationDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tnl_operation_duration_seconds", Help: "Completed application operation duration by fixed operation and outcome.", Buckets: DurationBucketsSeconds(),
		}, []string{"operation", "outcome"}),
		databaseQueryDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tnl_database_query_duration_seconds", Help: "Completed request-pool SQL duration observed by the driver, excluding pool acquisition.", Buckets: DurationBucketsSeconds(),
		}, []string{"operation", "outcome"}),
		databaseGuardDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tnl_database_guard_held_duration_seconds", Help: "Driver-observed interval from successful guard query completion through transaction completion; not exact PostgreSQL lock time.", Buckets: DurationBucketsSeconds(),
		}, []string{"operation", "outcome"}),
	}
	registered := []prometheus.Collector{
		info, collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	}
	if role == "control" || role == "standalone" {
		registered = append(registered, metrics.routingHistoryRows, metrics.routingHistorySkipped,
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "tnl_routing_history_retained_after_revision", Help: "Highest committed routing-history retention floor observed by this process."}, func() float64 { return float64(metrics.routingHistoryFloor.Load()) }))
		registered = append(registered, metrics.controlRequests, metrics.controlDuration, metrics.controlInFlight,
			metrics.readinessAttempts, metrics.readinessDuration, metrics.readinessAge, metrics.certificateWork, metrics.certificateDuration,
			metrics.databaseQueryDuration, metrics.databaseGuardDuration)
	}
	if role == "control" || role == "ingress" || role == "relay" || role == "standalone" {
		registered = append(registered, metrics.operationDuration)
	}
	if role == "ingress" || role == "standalone" {
		registered = append(registered,
			metrics.streams, metrics.capacityRejections, metrics.sourceLimiterRejects,
			metrics.sourceLimiterEntries, metrics.ipAllowlistDenials, metrics.forwardedBytes, metrics.relayAttempts,
			metrics.inspectionFailures, metrics.challengeRejections,
		)
		metrics.streams.WithLabelValues("ingress").Set(0)
	}
	if role == "relay" || role == "standalone" {
		registered = append(registered, metrics.relayLeases, metrics.publisherConnections)
		if role == "relay" {
			registered = append(registered, metrics.streams, metrics.capacityRejections)
		}
		metrics.streams.WithLabelValues("relay").Set(0)
	}
	registry.MustRegister(registered...)
	return metrics
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Gather captures this process's registry using only passive collectors.
func (m *Metrics) Gather() ([]*dto.MetricFamily, error) {
	return m.registry.Gather()
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

func (m *Metrics) SetIngressStreams(count int) {
	m.streams.WithLabelValues("ingress").Set(float64(count))
}

func (m *Metrics) AddRelayStreams(delta int) {
	m.streams.WithLabelValues("relay").Add(float64(delta))
}

func (m *Metrics) IncCapacityRejection(resource string) {
	m.capacityRejections.WithLabelValues(resource).Inc()
}

func (m *Metrics) IncInspectionFailure(stage string) {
	switch stage {
	case "deadline", "metadata", "client_hello", "hostname":
		m.inspectionFailures.WithLabelValues(stage).Inc()
	}
}

func (m *Metrics) IncChallengeRejection(reason string) {
	switch reason {
	case "unconfigured", "unavailable", "invalid_hostname", "uninitialized", "missing", "tombstone",
		"route_expired", "backend_expired", "ingress_unavailable", "invalid_projection":
		m.challengeRejections.WithLabelValues(reason).Inc()
	}
}

func (m *Metrics) IncSourceLimiterRejection() { m.sourceLimiterRejects.Inc() }

func (m *Metrics) SetSourceLimiterEntries(count int) { m.sourceLimiterEntries.Set(float64(count)) }

func (m *Metrics) IncIPAllowlistDenial() { m.ipAllowlistDenials.Inc() }

func (m *Metrics) AddForwardedBytes(direction string, count int64) {
	m.forwardedBytes.WithLabelValues(direction).Add(float64(count))
}

func (m *Metrics) ObserveRelayAttempt(slot, outcome string) {
	if slot != "0" && slot != "1" {
		slot = "unknown"
	}
	switch outcome {
	case "open_failed", "setup_failed", "committed_failed", "committed":
	default:
		outcome = "open_failed"
	}
	m.relayAttempts.WithLabelValues(slot, outcome).Inc()
}

func (m *Metrics) ObserveControlRequest(operation, outcome string, duration time.Duration) {
	m.controlRequests.WithLabelValues(operation, outcome).Inc()
	m.controlDuration.WithLabelValues(operation, outcome).Observe(duration.Seconds())
}

// Outcomes and stages are closed sets, independent of route and order identity.
func (m *Metrics) ObserveRouteSessionReadiness(outcome string, duration, age time.Duration) {
	switch outcome {
	case "ready", "certificate_missing", "connections_missing", "certificate_and_connections_missing", "error":
	default:
		outcome = "error"
	}
	m.readinessAttempts.WithLabelValues(outcome).Inc()
	m.readinessDuration.WithLabelValues(outcome).Observe(duration.Seconds())
	if outcome != "error" && age >= 0 {
		m.readinessAge.WithLabelValues(outcome).Observe(age.Seconds())
	}
}

func (m *Metrics) ObserveCertificateWork(stage, outcome string, duration time.Duration) {
	switch stage {
	case "pending", "authorizing", "ready_to_finalize", "finalizing", "failed", "canceled":
	default:
		stage = "other"
	}
	switch outcome {
	case "progress", "retry", "terminal", "save_failed":
	default:
		outcome = "retry"
	}
	m.certificateWork.WithLabelValues(stage, outcome).Inc()
	m.certificateDuration.WithLabelValues(stage, outcome).Observe(duration.Seconds())
}
