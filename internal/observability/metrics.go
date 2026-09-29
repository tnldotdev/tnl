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
	registry               *prometheus.Registry
	relayLeases            *prometheus.GaugeVec
	publisherConnections   prometheus.Gauge
	registeredConnections  prometheus.Gauge
	publisherExits         *prometheus.CounterVec
	ingressStreams         prometheus.Gauge
	relayStreams           prometheus.Gauge
	ingressConnections     *prometheus.GaugeVec
	visitorConnections     *prometheus.CounterVec
	visitorOpenDuration    *prometheus.HistogramVec
	relayStreamRejections  *prometheus.CounterVec
	capacityRejections     *prometheus.CounterVec
	drainingRejections     prometheus.Counter
	capacityLimits         *prometheus.GaugeVec
	inspectionFailures     *prometheus.CounterVec
	challengeRejections    *prometheus.CounterVec
	forwardedBytes         *prometheus.CounterVec
	relayAttempts          *prometheus.CounterVec
	apiDuration            *prometheus.HistogramVec
	apiInFlight            *prometheus.GaugeVec
	readinessDuration      *prometheus.HistogramVec
	readinessAge           *prometheus.HistogramVec
	certificateDuration    *prometheus.HistogramVec
	certificateMilestone   *prometheus.HistogramVec
	controlOperations      *prometheus.HistogramVec
	ingressOperations      *prometheus.HistogramVec
	relayOperations        *prometheus.HistogramVec
	databaseQueryDuration  *prometheus.HistogramVec
	databaseGuardDuration  *prometheus.HistogramVec
	recoveryDuration       prometheus.Histogram
	recoveryPending        prometheus.Gauge
	recoveryAttempts       *prometheus.CounterVec
	certificateClaims      *prometheus.CounterVec
	certificateTransitions *prometheus.CounterVec
	dnsWork                *prometheus.HistogramVec
	dnsTransitions         *prometheus.CounterVec
	usageWork              *prometheus.CounterVec
	usageItems             *prometheus.CounterVec
	usageReceiverDuration  *prometheus.HistogramVec
	usageRetained          prometheus.Gauge
	cleanupRuns            *prometheus.CounterVec
	cleanupItems           *prometheus.CounterVec
	cleanupLastSuccess     *prometheus.GaugeVec
	placementDecisions     *prometheus.CounterVec
	assignmentReplacements *prometheus.CounterVec
	routingHistoryFloor    atomic.Uint64
	routingHistoryRows     *prometheus.CounterVec
	routingHistorySkipped  prometheus.Counter
}

// New constructs an isolated registry for one tnld role.
func New(role string) *Metrics {
	registry := prometheus.NewRegistry()
	info := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tnl_process_info", Help: "Process role (one for this process).", ConstLabels: prometheus.Labels{"role": role},
	})
	info.Set(1)
	metrics := &Metrics{
		registry:              registry,
		routingHistoryRows:    prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_control_routing_history_cleanup_rows_total", Help: "Committed routing-history cleanup rows by action."}, []string{"action"}),
		routingHistorySkipped: prometheus.NewCounter(prometheus.CounterOpts{Name: "tnl_control_routing_history_cleanup_skipped_total", Help: "Cleanup batches skipped because another control holds the cleanup guard."}),
		relayLeases: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tnl_relay_local_leases", Help: "Relay leases held by this process by state; not a control-wide lease count.",
		}, []string{"state"}),
		publisherConnections:  prometheus.NewGauge(prometheus.GaugeOpts{Name: "tnl_relay_publisher_connections_ready", Help: "Publisher connections marked ready on relays in this process."}),
		registeredConnections: prometheus.NewGauge(prometheus.GaugeOpts{Name: "tnl_relay_publisher_connections_registered", Help: "Locally registered publisher connections, including those not yet ready; not authoritative database claims."}),
		publisherExits:        prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_relay_publisher_connection_exits_total", Help: "Ready publisher connections that ended, by expectedness."}, []string{"reason"}),
		ingressStreams:        prometheus.NewGauge(prometheus.GaugeOpts{Name: "tnl_ingress_backend_streams", Help: "Tracked backend streams including streams being opened, challenges, and denied connections."}),
		relayStreams:          prometheus.NewGauge(prometheus.GaugeOpts{Name: "tnl_relay_visitor_stream_slots_occupied", Help: "Occupied relay forwarding-stream slots, including opens in progress."}),
		ingressConnections:    prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "tnl_ingress_connections", Help: "Current ingress admission slots by fixed connection class."}, []string{"class"}),
		visitorConnections:    prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_ingress_visitor_connections_total", Help: "Classified ordinary visitor connections by forwarding outcome; forwarded does not imply visitor TLS success."}, []string{"outcome"}),
		visitorOpenDuration:   prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "tnl_ingress_visitor_stream_open_duration_seconds", Help: "Time from a classified visitor to a forwarding decision, excluding TLS and copy time.", Buckets: DurationBucketsSeconds()}, []string{"outcome"}),
		relayStreamRejections: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_relay_visitor_stream_rejections_total", Help: "Relay stream rejections other than capacity exhaustion, by fixed reason."}, []string{"reason"}),
		capacityRejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_admission_rejections_total", Help: "Admission rejected because a bounded resource was full.",
		}, []string{"resource"}),
		drainingRejections: prometheus.NewCounter(prometheus.CounterOpts{Name: "tnl_ingress_draining_rejections_total", Help: "Connections rejected because ingress was draining."}),
		capacityLimits: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tnl_admission_limit", Help: "Resolved admission limit by fixed resource; per-URL and per-hostname resources are per key.",
		}, []string{"resource"}),
		inspectionFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_ingress_inspection_failures_total", Help: "Ingress connections rejected before classification by fixed failure stage.",
		}, []string{"stage"}),
		challengeRejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_ingress_challenge_rejections_total", Help: "ACME TLS-ALPN connections rejected before relay forwarding by fixed reason.",
		}, []string{"reason"}),
		forwardedBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_ingress_forwarded_bytes_total", Help: "Bytes forwarded through ingress, recorded after a copy finishes.",
		}, []string{"direction"}),
		relayAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_ingress_relay_attempts_total", Help: "Ingress internal-forwarding attempts by connection slot and bounded outcome.",
		}, []string{"connection_slot", "outcome"}),
		apiDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tnl_control_api_request_duration_seconds", Help: "Control-served HTTP handler duration including long polls; count is the request total.", Buckets: DurationBucketsSeconds(),
		}, []string{"surface", "operation", "outcome"}),
		apiInFlight: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tnl_control_api_requests_in_flight", Help: "Control-served HTTP requests currently executing by API surface.",
		}, []string{"surface"}),
		readinessDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tnl_control_publish_run_readiness_duration_seconds", Help: "Time spent checking and publishing publish run readiness; count is the number of attempts.", Buckets: DurationBucketsSeconds(),
		}, []string{"outcome"}),
		readinessAge: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tnl_control_publish_run_readiness_age_seconds", Help: "Age of the publish run at a readiness decision; excludes other errors.",
			Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600},
		}, []string{"outcome"}),
		certificateDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tnl_control_certificate_work_duration_seconds", Help: "Certificate worker advance and save duration; count is the number of claimed iterations.", Buckets: DurationBucketsSeconds(),
		}, []string{"kind", "stage", "outcome"}),
		certificateMilestone: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tnl_control_public_url_certificate_milestone_age_seconds", Help: "Time from issuance creation to certificate availability or DNS cleanup; availability does not imply installation.",
			Buckets: []float64{1, 5, 10, 20, 30, 45, 60, 90, 120, 300, 600},
		}, []string{"milestone"}),
		controlOperations: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tnl_control_operation_duration_seconds", Help: "Completed control state operation duration by fixed operation and outcome.", Buckets: DurationBucketsSeconds(),
		}, []string{"operation", "outcome"}),
		ingressOperations: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tnl_ingress_operation_duration_seconds", Help: "Completed ingress operation duration by fixed operation and outcome.", Buckets: DurationBucketsSeconds(),
		}, []string{"operation", "outcome"}),
		relayOperations: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tnl_relay_operation_duration_seconds", Help: "Completed relay operation duration by fixed operation and outcome.", Buckets: DurationBucketsSeconds(),
		}, []string{"operation", "outcome"}),
		databaseQueryDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tnl_database_query_duration_seconds", Help: "Completed request-pool SQL duration observed by the driver, excluding pool acquisition.", Buckets: DurationBucketsSeconds(),
		}, []string{"operation", "outcome"}),
		databaseGuardDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "tnl_database_guard_held_duration_seconds", Help: "Driver-observed interval from successful guard query completion through transaction completion; not exact PostgreSQL lock time.", Buckets: DurationBucketsSeconds(),
		}, []string{"operation", "outcome"}),
		recoveryDuration:       prometheus.NewHistogram(prometheus.HistogramOpts{Name: "tnl_control_public_url_recovery_duration_seconds", Help: "Duration of newly committed public URL recovery observations on this control process.", Buckets: DurationBucketsSeconds()}),
		recoveryPending:        prometheus.NewGauge(prometheus.GaugeOpts{Name: "tnl_ingress_recovery_observations_pending", Help: "Recovery observations awaiting a successful or stale response."}),
		recoveryAttempts:       prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_ingress_recovery_observation_attempts_total", Help: "Recovery reporting attempts by bounded outcome."}, []string{"outcome"}),
		certificateClaims:      prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_control_certificate_claims_total", Help: "Certificate worker claims by certificate kind and outcome."}, []string{"kind", "outcome"}),
		certificateTransitions: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_control_certificate_transitions_total", Help: "Committed certificate work transitions by kind and resulting state."}, []string{"kind", "state"}),
		dnsWork:                prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "tnl_control_dns_work_duration_seconds", Help: "DNS worker phase duration; count is the number of attempts.", Buckets: DurationBucketsSeconds()}, []string{"kind", "phase", "outcome"}),
		dnsTransitions:         prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_control_dns_transitions_total", Help: "Committed DNS work transitions by kind and resulting state."}, []string{"kind", "state"}),
		usageWork:              prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_control_public_url_usage_work_total", Help: "Usage worker operations by fixed phase and outcome."}, []string{"phase", "outcome"}),
		usageItems:             prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_control_public_url_usage_items_total", Help: "Usage runs, buckets or deliveries committed by result."}, []string{"result"}),
		usageReceiverDuration:  prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "tnl_control_public_url_usage_receiver_duration_seconds", Help: "Usage receiver request duration by bounded outcome.", Buckets: DurationBucketsSeconds()}, []string{"outcome"}),
		usageRetained:          prometheus.NewGauge(prometheus.GaugeOpts{Name: "tnl_ingress_usage_retained_buckets", Help: "Ingress usage buckets retained in memory, including dirty and pending buckets."}),
		cleanupRuns:            prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_control_cleanup_runs_total", Help: "Cleanup calls by fixed kind and outcome."}, []string{"kind", "outcome"}),
		cleanupItems:           prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_control_cleanup_items_total", Help: "Committed items removed by cleanup kind."}, []string{"kind"}),
		cleanupLastSuccess:     prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "tnl_control_cleanup_last_success_timestamp_seconds", Help: "Unix time of last successful cleanup by kind; zero before success."}, []string{"kind"}),
		placementDecisions:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_control_placement_decisions_total", Help: "Publish run placement decisions by action and bounded result."}, []string{"action", "outcome"}),
		assignmentReplacements: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_control_connection_assignments_replaced_total", Help: "Committed replacement of connection assignments by fixed reason."}, []string{"reason"}),
	}
	registered := []prometheus.Collector{
		info, collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	}
	if role == "control" || role == "standalone" {
		registered = append(registered, metrics.routingHistoryRows, metrics.routingHistorySkipped,
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "tnl_control_routing_history_retained_after_revision", Help: "Highest committed routing-history retention floor observed by this process."}, func() float64 { return float64(metrics.routingHistoryFloor.Load()) }))
		registered = append(registered, metrics.apiDuration, metrics.apiInFlight,
			metrics.readinessDuration, metrics.readinessAge, metrics.certificateDuration, metrics.certificateMilestone,
			metrics.databaseQueryDuration, metrics.databaseGuardDuration, metrics.controlOperations, metrics.recoveryDuration,
			metrics.certificateClaims, metrics.certificateTransitions, metrics.dnsWork, metrics.dnsTransitions,
			metrics.usageWork, metrics.usageItems, metrics.usageReceiverDuration,
			metrics.cleanupRuns, metrics.cleanupItems, metrics.cleanupLastSuccess, metrics.placementDecisions, metrics.assignmentReplacements)
	}
	registered = append(registered, metrics.capacityLimits)
	if role == "ingress" || role == "standalone" {
		registered = append(registered,
			metrics.ingressStreams, metrics.ingressConnections, metrics.visitorConnections, metrics.visitorOpenDuration,
			metrics.capacityRejections, metrics.drainingRejections, metrics.forwardedBytes, metrics.relayAttempts,
			metrics.inspectionFailures, metrics.challengeRejections, metrics.ingressOperations,
			metrics.recoveryPending, metrics.recoveryAttempts, metrics.usageRetained,
		)
	}
	if role == "ingress" || role == "standalone" {
		for _, class := range []string{"client_hello", "public", "denied", "challenge", "control", "relay_tcp"} {
			metrics.ingressConnections.WithLabelValues(class).Set(0)
		}
	}
	if role == "relay" || role == "standalone" {
		registered = append(registered, metrics.relayLeases, metrics.publisherConnections, metrics.registeredConnections,
			metrics.publisherExits, metrics.relayStreamRejections, metrics.relayStreams, metrics.relayOperations)
		if role == "relay" {
			registered = append(registered, metrics.capacityRejections)
		}
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
	if state == "ready" {
		m.publisherConnections.Set(float64(count))
	}
}

func (m *Metrics) AddPublisherConnections(state string, delta int) {
	if state == "ready" {
		m.publisherConnections.Add(float64(delta))
	}
}

func (m *Metrics) SetIngressStreams(count int) {
	m.ingressStreams.Set(float64(count))
}

func (m *Metrics) AddRelayStreams(delta int) {
	m.relayStreams.Add(float64(delta))
}

func (m *Metrics) IncCapacityRejection(resource string) {
	if resource == "draining" {
		m.drainingRejections.Inc()
		return
	}
	m.capacityRejections.WithLabelValues(resource).Inc()
}

func (m *Metrics) IncDrainingRejection() { m.drainingRejections.Inc() }

func (m *Metrics) SetCapacityLimit(resource string, limit int64) {
	m.capacityLimits.WithLabelValues(resource).Set(float64(limit))
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
		"public_url_expired", "backend_expired", "ingress_unavailable", "invalid_projection":
		m.challengeRejections.WithLabelValues(reason).Inc()
	}
}

func (m *Metrics) AddForwardedBytes(direction string, count int64) {
	m.forwardedBytes.WithLabelValues(direction).Add(float64(count))
}

func (m *Metrics) ObserveRelayAttempt(slot, outcome string) {
	if slot != "0" && slot != "1" {
		slot = "unknown"
	}
	switch outcome {
	case "open_failed", "setup_failed", "committed_failed", "committed", "other":
	default:
		outcome = "other"
	}
	m.relayAttempts.WithLabelValues(slot, outcome).Inc()
}

func (m *Metrics) ObserveAPIRequest(surface, operation, outcome string, duration time.Duration) {
	m.apiDuration.WithLabelValues(surface, operation, outcome).Observe(duration.Seconds())
}

// Outcomes and stages are closed sets, independent of route and order identity.
func (m *Metrics) ObservePublishRunReadiness(outcome string, duration, age time.Duration) {
	switch outcome {
	case "ready", "certificate_missing", "connections_missing", "certificate_and_connections_missing", "error":
	default:
		outcome = "error"
	}
	m.readinessDuration.WithLabelValues(outcome).Observe(duration.Seconds())
	if outcome != "error" && age >= 0 {
		m.readinessAge.WithLabelValues(outcome).Observe(age.Seconds())
	}
}

func (m *Metrics) ObserveCertificateWork(stage, outcome string, duration time.Duration) {
	m.ObserveCertificateIteration("public_url", stage, outcome, duration)
}

func (m *Metrics) ObserveCertificateIteration(kind, stage, outcome string, duration time.Duration) {
	if kind != "public_url" && kind != "relay" {
		return
	}
	switch stage {
	case "pending", "authorizing", "ready_to_finalize", "finalizing", "failed", "canceled", "waiting_for_install", "installed", "presenting", "presented", "validating", "cleaning", "failed_cleaning", "complete":
	default:
		stage = "other"
	}
	switch outcome {
	case "progress", "retry", "terminal", "save_failed":
	default:
		outcome = "retry"
	}
	m.certificateDuration.WithLabelValues(kind, stage, outcome).Observe(duration.Seconds())
}

func (m *Metrics) ObserveCertificateMilestone(milestone string, age time.Duration) {
	if milestone != "ready" && milestone != "cleanup" || age < 0 {
		return
	}
	m.certificateMilestone.WithLabelValues(milestone).Observe(age.Seconds())
}
