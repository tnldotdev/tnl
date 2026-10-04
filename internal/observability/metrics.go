package observability

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/tnldotdev/tnl/internal/readiness"
)

// Metrics owns a process-local Prometheus registry.
type Metrics struct {
	registry                *prometheus.Registry
	relayLeaseMu            sync.Mutex
	relayLeaseExpiry        map[string]time.Time
	relayCertificateExpiry  map[string]time.Time
	relayLeases             *prometheus.GaugeVec
	publisherConnections    prometheus.Gauge
	registeredConnections   prometheus.Gauge
	publisherExits          *prometheus.CounterVec
	ingressStreams          prometheus.Gauge
	relayStreams            prometheus.Gauge
	ingressConnections      *prometheus.GaugeVec
	visitorConnections      *prometheus.CounterVec
	visitorOpenDuration     *prometheus.HistogramVec
	relayStreamRejections   *prometheus.CounterVec
	capacityRejections      *prometheus.CounterVec
	drainingRejections      prometheus.Counter
	capacityLimits          *prometheus.GaugeVec
	inspectionFailures      *prometheus.CounterVec
	challengeRejections     *prometheus.CounterVec
	forwardedBytes          *prometheus.CounterVec
	relayAttempts           *prometheus.CounterVec
	apiDuration             *prometheus.HistogramVec
	apiInFlight             *prometheus.GaugeVec
	readinessDuration       *prometheus.HistogramVec
	readinessAge            *prometheus.HistogramVec
	certificateDuration     *prometheus.HistogramVec
	certificateMilestone    *prometheus.HistogramVec
	controlOperations       *prometheus.HistogramVec
	ingressOperations       *prometheus.HistogramVec
	relayOperations         *prometheus.HistogramVec
	databaseQueryDuration   *prometheus.HistogramVec
	databaseGuardDuration   *prometheus.HistogramVec
	databaseAcquireDuration *prometheus.HistogramVec
	databaseFailures        *prometheus.CounterVec
	recoveryDuration        prometheus.Histogram
	recoveryPending         prometheus.Gauge
	recoveryAttempts        *prometheus.CounterVec
	certificateClaims       *prometheus.CounterVec
	certificateTransitions  *prometheus.CounterVec
	dnsWork                 *prometheus.HistogramVec
	dnsTransitions          *prometheus.CounterVec
	usageWork               *prometheus.CounterVec
	usageItems              *prometheus.CounterVec
	usageReceiverDuration   *prometheus.HistogramVec
	usageLastSuccess        *prometheus.GaugeVec
	usageRetained           prometheus.Gauge
	cleanupRuns             *prometheus.CounterVec
	cleanupItems            *prometheus.CounterVec
	cleanupLastSuccess      *prometheus.GaugeVec
	guestTrialStats         *prometheus.GaugeVec
	placementDecisions      *prometheus.CounterVec
	assignmentReplacements  *prometheus.CounterVec
	routingHistoryFloor     atomic.Uint64
	routingHistoryRows      *prometheus.CounterVec
	routingHistorySkipped   prometheus.Counter
}

// New constructs an isolated registry for one tnld role.
func New(role string) *Metrics {
	registry := prometheus.NewRegistry()
	info := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tnl_process_info", Help: "Process role (one for this process).", ConstLabels: prometheus.Labels{"role": role},
	})
	info.Set(1)
	metrics := &Metrics{
		registry:               registry,
		relayLeaseExpiry:       make(map[string]time.Time),
		relayCertificateExpiry: make(map[string]time.Time),
		routingHistoryRows:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_control_routing_history_cleanup_rows_total", Help: "Committed routing-history cleanup rows by action."}, []string{"action"}),
		routingHistorySkipped:  prometheus.NewCounter(prometheus.CounterOpts{Name: "tnl_control_routing_history_cleanup_skipped_total", Help: "Cleanup batches skipped because another control holds the cleanup guard."}),
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
		databaseAcquireDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "tnl_database_pool_acquire_duration_seconds", Help: "Time to acquire a request-pool connection, including waits and failed acquisitions.", Buckets: DurationBucketsSeconds()}, []string{"outcome"}),
		databaseFailures:        prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_database_failures_total", Help: "Request-pool failures by fixed boundary and outcome; acquire has no SQL operation name."}, []string{"phase", "outcome"}),
		recoveryDuration:        prometheus.NewHistogram(prometheus.HistogramOpts{Name: "tnl_control_public_url_recovery_duration_seconds", Help: "Duration of newly committed public URL recovery observations on this control process.", Buckets: DurationBucketsSeconds()}),
		recoveryPending:         prometheus.NewGauge(prometheus.GaugeOpts{Name: "tnl_ingress_recovery_observations_pending", Help: "Recovery observations awaiting a successful or stale response."}),
		recoveryAttempts:        prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_ingress_recovery_observation_attempts_total", Help: "Recovery reporting attempts by bounded outcome."}, []string{"outcome"}),
		certificateClaims:       prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_control_certificate_claims_total", Help: "Certificate worker claims by certificate kind and outcome."}, []string{"kind", "outcome"}),
		certificateTransitions:  prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_control_certificate_transitions_total", Help: "Committed certificate work transitions by kind and resulting state."}, []string{"kind", "state"}),
		dnsWork:                 prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "tnl_control_dns_work_duration_seconds", Help: "DNS worker phase duration; count is the number of attempts.", Buckets: DurationBucketsSeconds()}, []string{"kind", "phase", "outcome"}),
		dnsTransitions:          prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_control_dns_transitions_total", Help: "Committed DNS work transitions by kind and resulting state."}, []string{"kind", "state"}),
		usageWork:               prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_control_public_url_usage_work_total", Help: "Usage worker operations by fixed phase and outcome."}, []string{"phase", "outcome"}),
		usageItems:              prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_control_public_url_usage_items_total", Help: "Usage runs, buckets or deliveries committed by result."}, []string{"result"}),
		usageReceiverDuration:   prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "tnl_control_public_url_usage_receiver_duration_seconds", Help: "Usage receiver request duration by bounded outcome.", Buckets: DurationBucketsSeconds()}, []string{"outcome"}),
		usageLastSuccess:        prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "tnl_control_public_url_usage_last_success_timestamp_seconds", Help: "Unix time of the last successful finalization call or committed delivery; zero before success."}, []string{"phase"}),
		usageRetained:           prometheus.NewGauge(prometheus.GaugeOpts{Name: "tnl_ingress_usage_retained_buckets", Help: "Ingress usage buckets retained in memory, including dirty and pending buckets."}),
		cleanupRuns:             prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_control_cleanup_runs_total", Help: "Cleanup calls by fixed kind and outcome."}, []string{"kind", "outcome"}),
		cleanupItems:            prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_control_cleanup_items_total", Help: "Committed items removed by cleanup kind."}, []string{"kind"}),
		cleanupLastSuccess:      prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "tnl_control_cleanup_last_success_timestamp_seconds", Help: "Unix time of last successful cleanup by kind; zero before success."}, []string{"kind"}),
		guestTrialStats:         prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "tnl_control_guest_trials_last_24h", Help: "Service-wide trial counts from committed state over the last 24 hours; use max rather than sum across control replicas."}, []string{"stage"}),
		placementDecisions:      prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_control_placement_decisions_total", Help: "Publish run placement decisions by action and bounded result."}, []string{"action", "outcome"}),
		assignmentReplacements:  prometheus.NewCounterVec(prometheus.CounterOpts{Name: "tnl_control_connection_assignments_replaced_total", Help: "Committed replacement of connection assignments by fixed reason."}, []string{"reason"}),
	}
	registered := []prometheus.Collector{
		info, collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	}
	if role == "control" || role == "standalone" {
		registered = append(registered, metrics.routingHistoryRows, metrics.routingHistorySkipped,
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "tnl_control_routing_history_retained_after_revision", Help: "Highest committed routing-history retention floor observed by this process."}, func() float64 { return float64(metrics.routingHistoryFloor.Load()) }))
		registered = append(registered, metrics.apiDuration, metrics.apiInFlight,
			metrics.readinessDuration, metrics.readinessAge, metrics.certificateDuration, metrics.certificateMilestone,
			metrics.databaseQueryDuration, metrics.databaseGuardDuration, metrics.databaseAcquireDuration, metrics.databaseFailures, metrics.controlOperations, metrics.recoveryDuration,
			metrics.certificateClaims, metrics.certificateTransitions, metrics.dnsWork, metrics.dnsTransitions,
			metrics.usageWork, metrics.usageItems, metrics.usageReceiverDuration, metrics.usageLastSuccess,
			metrics.cleanupRuns, metrics.cleanupItems, metrics.cleanupLastSuccess, metrics.placementDecisions, metrics.assignmentReplacements)
		registered = append(registered, metrics.guestTrialStats)
		for _, stage := range []string{"issued", "allocated", "ready", "expired", "ready_limit", "transfer_limit"} {
			metrics.guestTrialStats.WithLabelValues(stage).Set(0)
		}
		for _, surface := range []string{"control", "authority", "private_ingress", "private_relay"} {
			metrics.apiInFlight.WithLabelValues(surface).Set(0)
		}
		for _, phase := range []string{"finalize", "deliver"} {
			metrics.usageLastSuccess.WithLabelValues(phase).Set(0)
		}
	}
	registered = append(registered, metrics.capacityLimits)
	if role == "ingress" || role == "standalone" {
		registered = append(registered,
			metrics.ingressStreams, metrics.ingressConnections, metrics.visitorConnections, metrics.visitorOpenDuration,
			metrics.capacityRejections, metrics.drainingRejections, metrics.forwardedBytes, metrics.relayAttempts,
			metrics.inspectionFailures, metrics.challengeRejections, metrics.ingressOperations,
			metrics.recoveryPending, metrics.recoveryAttempts, metrics.usageRetained,
		)
		for _, class := range []string{"client_hello", "public", "denied", "challenge", "control", "relay_tcp"} {
			metrics.ingressConnections.WithLabelValues(class).Set(0)
		}
	}
	if role == "relay" || role == "standalone" {
		registered = append(registered, metrics.relayLeases, metrics.publisherConnections, metrics.registeredConnections,
			metrics.publisherExits, metrics.relayStreamRejections, metrics.relayStreams, metrics.relayOperations,
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "tnl_relay_earliest_lease_expiration_timestamp_seconds", Help: "Earliest known relay lease expiration in this process; zero without a lease."}, metrics.earliestRelayLeaseExpiry),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "tnl_relay_transport_certificate_expiration_timestamp_seconds", Help: "Earliest locally known relay transport certificate expiry; zero before material is observed."}, metrics.earliestRelayCertificateExpiry))
		if role == "relay" {
			registered = append(registered, metrics.capacityRejections)
		}
	}
	registry.MustRegister(registered...)
	return metrics
}

func (m *Metrics) SetRelayLeaseExpiry(identity string, expires time.Time) {
	m.relayLeaseMu.Lock()
	defer m.relayLeaseMu.Unlock()
	if expires.IsZero() {
		delete(m.relayLeaseExpiry, identity)
	} else {
		m.relayLeaseExpiry[identity] = expires
	}
}

func (m *Metrics) earliestRelayLeaseExpiry() float64 {
	m.relayLeaseMu.Lock()
	defer m.relayLeaseMu.Unlock()
	return earliestExpiry(m.relayLeaseExpiry)
}

func (m *Metrics) SetRelayCertificateExpiry(identity string, expires time.Time) {
	m.relayLeaseMu.Lock()
	defer m.relayLeaseMu.Unlock()
	if expires.IsZero() {
		delete(m.relayCertificateExpiry, identity)
	} else {
		m.relayCertificateExpiry[identity] = expires
	}
}

func (m *Metrics) earliestRelayCertificateExpiry() float64 {
	m.relayLeaseMu.Lock()
	defer m.relayLeaseMu.Unlock()
	return earliestExpiry(m.relayCertificateExpiry)
}

func earliestExpiry(expiresByIdentity map[string]time.Time) float64 {
	var earliest time.Time
	for _, expires := range expiresByIdentity {
		if earliest.IsZero() || expires.Before(earliest) {
			earliest = expires
		}
	}
	return routingTimestamp(earliest)
}

// RegisterIngressLease reads a local controller snapshot without external I/O.
func (m *Metrics) RegisterIngressLease(source func() time.Time) {
	m.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "tnl_ingress_lease_expiration_timestamp_seconds", Help: "Local ingress lease expiration; zero before registration or after lease loss.",
	}, func() float64 { return routingTimestamp(source()) }))
}

// RegisterControlCertificate reads certificate material already in this process.
func (m *Metrics) RegisterControlCertificate(source func() time.Time) {
	m.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "tnl_control_tls_certificate_expiration_timestamp_seconds", Help: "Earliest locally loaded public control certificate expiry; zero when any configured hostname is not yet loaded.",
	}, func() float64 { return routingTimestamp(source()) }))
}

// SetGuestTrialStats observes committed service-wide counts without identity labels.
func (m *Metrics) SetGuestTrialStats(issued, allocated, ready, expired, readyLimit, transferLimit int64) {
	for stage, count := range map[string]int64{
		"issued": issued, "allocated": allocated, "ready": ready,
		"expired": expired, "ready_limit": readyLimit, "transfer_limit": transferLimit,
	} {
		if count >= 0 {
			m.guestTrialStats.WithLabelValues(stage).Set(float64(count))
		}
	}
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

func (m *Metrics) SetReadyPublisherConnections(count int) { m.publisherConnections.Set(float64(count)) }

func (m *Metrics) AddReadyPublisherConnections(delta int) { m.publisherConnections.Add(float64(delta)) }

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
	if !admissionResource(resource) {
		resource = "other"
	}
	m.capacityRejections.WithLabelValues(resource).Inc()
}

func (m *Metrics) IncDrainingRejection() { m.drainingRejections.Inc() }

func (m *Metrics) SetCapacityLimit(resource string, limit int64) {
	if !admissionResource(resource) || limit < 0 {
		return
	}
	m.capacityLimits.WithLabelValues(resource).Set(float64(limit))
}

func admissionResource(resource string) bool {
	switch resource {
	case "client_hello_connections", "public_connections", "public_url_connections",
		"denied_connections", "denied_public_url_connections", "challenge_connections",
		"challenge_hostname_connections", "control_connections", "relay_tcp_connections",
		"publisher_connections", "relay_streams":
		return true
	}
	return false
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

func (m *Metrics) ObserveRelayAttempt(slot string, outcome RelayAttemptOutcome) {
	if slot != "0" && slot != "1" {
		slot = "unknown"
	}
	switch outcome {
	case RelayAttemptOpenFailed, RelayAttemptSetupFailed, RelayAttemptCommittedFailed, RelayAttemptCommitted, RelayAttemptOther:
	default:
		outcome = RelayAttemptOther
	}
	m.relayAttempts.WithLabelValues(slot, string(outcome)).Inc()
}

func (m *Metrics) ObserveAPIRequest(surface, operation string, outcome APIRequestOutcome, duration time.Duration) {
	m.apiDuration.WithLabelValues(surface, operation, string(outcome)).Observe(duration.Seconds())
}

// outcomes and stages are closed sets, independent of public URL and order identity.
func (m *Metrics) ObservePublishRunReadiness(outcome readiness.Outcome, duration, age time.Duration) {
	switch outcome {
	case readiness.Ready, readiness.CertificateMissing, readiness.ConnectionsMissing,
		readiness.CertificateAndConnectionsMissing, readiness.DNSPending, readiness.DNSFailed, readiness.Error:
	default:
		outcome = readiness.Error
	}
	m.readinessDuration.WithLabelValues(string(outcome)).Observe(duration.Seconds())
	if outcome != readiness.Error && age >= 0 {
		m.readinessAge.WithLabelValues(string(outcome)).Observe(age.Seconds())
	}
}

func (m *Metrics) ObserveCertificateWork(stage string, outcome CertificateWorkOutcome, duration time.Duration) {
	m.ObserveCertificateIteration("public_url", stage, outcome, duration)
}

func (m *Metrics) ObserveCertificateIteration(kind, stage string, outcome CertificateWorkOutcome, duration time.Duration) {
	if kind != "public_url" && kind != "relay" {
		return
	}
	switch stage {
	case "pending", "authorizing", "ready_to_finalize", "finalizing", "failed", "canceled", "waiting_for_install", "installed", "presenting", "presented", "validating", "cleaning", "failed_cleaning", "complete":
	default:
		stage = "other"
	}
	switch outcome {
	case CertificateProgress, CertificateRetry, CertificateTerminal, CertificateSaveFailed:
	default:
		outcome = CertificateRetry
	}
	m.certificateDuration.WithLabelValues(kind, stage, string(outcome)).Observe(duration.Seconds())
}

func (m *Metrics) ObserveCertificateMilestone(milestone string, age time.Duration) {
	if milestone != "ready" && milestone != "cleanup" || age < 0 {
		return
	}
	m.certificateMilestone.WithLabelValues(milestone).Observe(age.Seconds())
}
