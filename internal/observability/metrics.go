package observability

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/tnldotdev/tnl/internal/policy/readiness"
	"go.opentelemetry.io/otel/metric"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Metrics owns one process's OTel instruments, providers, and scrape exporter.
type Metrics struct {
	clientOperations            *histogram
	clientLifecycle             *counter
	publisherData               publisherData
	targetDiscovery             *histogram
	targetDiscoveryCache        *counter
	targetDiscoverySuccess      *gauge
	relayBytes                  *counter
	relayCompletions            *counter
	meter                       metric.Meter
	meterProvider               *sdkmetric.MeterProvider
	tracerProvider              *sdktrace.TracerProvider
	loggerProvider              *sdklog.LoggerProvider
	spanQueue                   *spanQueue
	logProcessor                *sdklog.BatchProcessor
	cancelExports               context.CancelFunc
	resource                    *resource.Resource
	publisherOperations         metric.Float64Histogram
	publisherLease              metric.Float64Gauge
	publisherReadiness          metric.Float64Gauge
	publisherReadinessMetrics   publisherReadinessMetrics
	publisherConnectionAttempts metric.Int64Counter
	authDecisions               *counter
	serviceAudit                *counter
	registry                    *prometheus.Registry
	runtimeRegistry             *prometheus.Registry
	relayLeaseMu                sync.Mutex
	relayLeaseExpiry            map[string]time.Time
	relayCertificateExpiry      map[string]time.Time
	relayLeases                 *gauge
	publisherConnections        *gauge
	registeredConnections       *gauge
	publisherExits              *counter
	ingressStreams              *gauge
	relayStreams                *gauge
	ingressConnections          *gauge
	visitorConnections          *counter
	visitorOpenDuration         *histogram
	relayStreamRejections       *counter
	capacityRejections          *counter
	drainingRejections          *counter
	capacityLimits              *gauge
	inspectionFailures          *counter
	forwardedBytes              *counter
	trafficAdmissions           *counter
	relayAttempts               *counter
	apiDuration                 *histogram
	apiInFlight                 *gauge
	webhookProviderSources      *counter
	publicURLsCreated           *counter
	publishRunsReady            *counter
	readinessDuration           *histogram
	readinessAge                *histogram
	certificateDuration         *histogram
	certificateMilestone        *histogram
	controlOperations           *histogram
	publisherruntime            *histogram
	ingressOperations           *histogram
	relayOperations             *histogram
	databaseQueryDuration       *histogram
	databaseGuardDuration       *histogram
	databaseAcquireDuration     *histogram
	databaseFailures            *counter
	recoveryDuration            *histogram
	recoveryPending             *gauge
	recoveryAttempts            *counter
	certificateClaims           *counter
	certificateOrders           *counter
	certificateTransitions      *counter
	dnsWork                     *histogram
	dnsTransitions              *counter
	usageWork                   *counter
	usageItems                  *counter
	usageReceiverDuration       *histogram
	usageLastSuccess            *gauge
	usageRetained               *gauge
	cleanupRuns                 *counter
	cleanupItems                *counter
	cleanupLastSuccess          *gauge
	portInventory               atomic.Pointer[portInventory]
	guestTrialStats             *gauge
	placementDecisions          *counter
	assignmentReplacements      *counter
	routingHistoryFloor         atomic.Uint64
	routingHistoryRows          *counter
	routingHistorySkipped       *counter
}

// New constructs an isolated, local-only owner. it never reads export settings.
func New(role string) *Metrics {
	m, err := newOwner(role, Config{})
	if err != nil {
		panic(err)
	}
	return m
}

func (metrics *Metrics) initInstruments(role Role) {
	m := metrics.meter
	metrics.clientOperations = newHistogram(m, "tnl_client_operation_duration_seconds", "Finite native CLI and private IPC operations; excludes process lifetime and application work.", DurationBucketsSeconds(), Operation, OutcomeKey)
	metrics.clientLifecycle = newCounter(m, "tnl_client_lifecycle_events_total", "Native app registration and publication-ready transitions, emitted once by the lifecycle owner; reads do not emit transitions.", Event)
	metrics.initPublisherReadiness()
	metrics.initPublisherData()
	metrics.targetDiscovery = newHistogram(m, "tnl_target_discovery_duration_seconds", "Publisher AWS metadata refresh duration by fixed provider, target type, protocol and result; excludes cache hits.", DurationBucketsSeconds(), targetProvider, targetType, ServiceProtocol, targetDiscoveryOutcome)
	metrics.targetDiscoveryCache = newCounter(m, "tnl_target_discovery_cache_lookups_total", "Publisher cache decisions by fixed type, protocol and health; last_success is bounded transient fallback, never a new success.", targetProvider, targetType, ServiceProtocol, State)
	metrics.targetDiscoverySuccess = newGauge(m, "tnl_target_discovery_last_success_timestamp_seconds", "Last success of the target observed by the most recent lookup in this fixed type/protocol class; not a per-resource freshness guarantee.", targetProvider, targetType, ServiceProtocol)
	metrics.publisherOperations = newHistogram(m, "tnl_publisher_operation_duration_seconds", "Finite publisher operations by authenticated identity and bounded outcome.", DurationBucketsSeconds(), Operation, OutcomeKey, Component, ServiceProtocol, AccessPath, Exposure, TLSLeg, Transport, TransportPreference, ConnectionSlot).instrument
	describe(m, "tnl_publisher_lease_expiration_timestamp_seconds", "Last confirmed control lease; failed refresh never extends it.", KindGauge, nil, Component, ServiceProtocol, AccessPath, Exposure)
	describe(m, "tnl_publisher_readiness_check_timestamp_seconds", "Most recent readiness decision; timestamp requires freshness checks.", KindGauge, nil, State, Component, ServiceProtocol, AccessPath, Exposure)
	describe(m, "tnl_publisher_connection_attempts_total", "Completed publisher connection races by selected transport and preference.", KindCounter, nil, Transport, TransportPreference, OutcomeKey, Component, ServiceProtocol, AccessPath, Exposure)
	metrics.publisherLease, _ = m.Float64Gauge("tnl_publisher_lease_expiration_timestamp_seconds", metric.WithDescription("Last confirmed control lease expiration, not locally extended on failed refreshes."))
	metrics.publisherReadiness, _ = m.Float64Gauge("tnl_publisher_readiness_check_timestamp_seconds", metric.WithDescription("Most recent readiness decision by outcome; use its timestamp to check freshness."))
	metrics.publisherConnectionAttempts, _ = m.Int64Counter("tnl_publisher_connection_attempts_total", metric.WithDescription("Completed connection races by selected transport and initial preference; replacements and failed attempts count independently."))
	metrics.authDecisions = newCounter(m, "tnl_authorization_decisions_total", "Semantic authorization results, independent of HTTP status.", Operation, OutcomeKey)
	metrics.relayLeaseExpiry = make(map[string]time.Time)
	metrics.relayCertificateExpiry = make(map[string]time.Time)
	newGauge(m, "tnl_process_info", "Process role (one for this process).", RoleKey).With(RoleKey.Dimension(role)).Set(1)
	metrics.serviceAudit = newCounter(m, "tnl_service_audit_events_total", "Process-local service audit queue and ingestion counts by fixed result; queued observations can be lost on a crash.", Event)
	metrics.routingHistoryRows = newCounter(m, "tnl_control_routing_history_cleanup_rows_total", "Committed routing-history cleanup rows by action.", Operation)
	metrics.routingHistorySkipped = newCounter(m, "tnl_control_routing_history_cleanup_skipped_total", "Cleanup batches skipped because another control holds the cleanup guard.")
	metrics.relayLeases = newGauge(m, "tnl_relay_local_leases", "Relay leases held by this process by state; not a control-wide lease count.", State)
	metrics.publisherConnections = newGauge(m, "tnl_relay_publisher_connections_ready", "Publisher connections marked ready on relays in this process.")
	metrics.registeredConnections = newGauge(m, "tnl_relay_publisher_connections_registered", "Locally registered publisher connections, including those not yet ready; not authoritative database claims.")
	metrics.publisherExits = newCounter(m, "tnl_relay_publisher_connection_exits_total", "Ready publisher connections that ended, by expectedness.", Reason)
	metrics.ingressStreams = newGauge(m, "tnl_ingress_backend_streams", "Tracked backend streams including streams being opened, challenges, and denied connections.")
	metrics.relayStreams = newGauge(m, "tnl_relay_visitor_stream_slots_occupied", "Occupied relay forwarding-stream slots, including opens in progress.")
	metrics.ingressConnections = newGauge(m, "tnl_ingress_connections", "Current ingress admission slots by fixed connection class.", connectionClass)
	metrics.visitorConnections = newCounter(m, "tnl_ingress_visitor_connections_total", "Classified visitor connections by forwarding outcome; forwarded does not imply visitor TLS success.", OutcomeKey)
	metrics.visitorOpenDuration = newHistogram(m, "tnl_ingress_visitor_stream_open_duration_seconds", "Time from a classified visitor to a forwarding decision, excluding TLS and copy time.", DurationBucketsSeconds(), OutcomeKey)
	metrics.relayStreamRejections = newCounter(m, "tnl_relay_visitor_stream_rejections_total", "Relay stream rejections other than capacity exhaustion, by fixed reason.", Reason)
	metrics.capacityRejections = newCounter(m, "tnl_admission_rejections_total", "Admission rejected because a bounded resource was full.", CapacityResource)
	metrics.drainingRejections = newCounter(m, "tnl_ingress_draining_rejections_total", "Connections rejected because ingress was draining.")
	metrics.capacityLimits = newGauge(m, "tnl_admission_limit", "Resolved admission limit by fixed resource; per-URL and per-hostname resources are per key.", CapacityResource)
	metrics.inspectionFailures = newCounter(m, "tnl_ingress_inspection_failures_total", "Ingress connections rejected before classification by fixed failure stage.", Operation)
	metrics.forwardedBytes = newCounter(m, "tnl_ingress_forwarded_bytes_total", "Bytes forwarded through ingress, recorded after a copy finishes.", Direction)
	metrics.trafficAdmissions = newCounter(m, "tnl_ingress_traffic_admissions_total", "Process-local traffic decisions by fixed stage and result; excludes identities and network addresses.", Operation, OutcomeKey)
	metrics.relayAttempts = newCounter(m, "tnl_ingress_relay_attempts_total", "Ingress internal-forwarding attempts by connection slot and bounded outcome.", ConnectionSlot, OutcomeKey)
	metrics.apiDuration = newHistogram(m, "tnl_api_request_duration_seconds", "tnl API handler duration including long polls; count is the request total.", DurationBucketsSeconds(), Component, HTTPMethod, HTTPRoute, OutcomeKey)
	metrics.apiInFlight = newGauge(m, "tnl_api_requests_in_flight", "tnl API requests currently executing by component.", Component)
	metrics.webhookProviderSources = newCounter(m, "tnl_control_webhook_provider_source_requests_total", "Webhook sender-policy lookups by fixed provider and bounded outcome; not configured endpoints or webhook deliveries.", providerKey, OutcomeKey)
	metrics.publicURLsCreated = newCounter(m, "tnl_control_public_urls_created_total", "New public URLs committed by client-declared purpose; excludes idempotent retries.", publicURLPurpose)
	metrics.publishRunsReady = newCounter(m, "tnl_control_publish_runs_ready_total", "Publish runs first marked ready by their saved public URL purpose.", publicURLPurpose)
	metrics.readinessDuration = newHistogram(m, "tnl_control_publish_run_readiness_duration_seconds", "Time spent checking and publishing publish run readiness; count is the number of attempts.", DurationBucketsSeconds(), State)
	metrics.readinessAge = newHistogram(m, "tnl_control_publish_run_readiness_age_seconds", "Age of the publish run at a readiness decision; excludes other errors.", []float64{1, 5, 10, 30, 60, 120, 300, 600}, State)
	metrics.certificateDuration = newHistogram(m, "tnl_control_certificate_work_duration_seconds", "Certificate worker advance and save duration; count is the number of claimed iterations.", DurationBucketsSeconds(), CertificateKind, Operation, OutcomeKey)
	metrics.certificateMilestone = newHistogram(m, "tnl_control_certificate_milestone_age_seconds", "Time from issuance creation to certificate availability or DNS cleanup; availability does not imply installation.", []float64{1, 5, 10, 20, 30, 45, 60, 90, 120, 300, 600}, CertificateKind, Event)
	metrics.controlOperations = newHistogram(m, "tnl_control_operation_duration_seconds", "Completed control state operation duration by fixed operation and outcome.", DurationBucketsSeconds(), Operation, OutcomeKey)
	metrics.publisherruntime = newHistogram(m, "tnl_control_publisher_runtime_duration_seconds", "Signed publisher runtime inspect/start/renew/stop decisions; identity dimensions attach only after proof verification.", DurationBucketsSeconds(), Operation, OutcomeKey, TeamID, PublisherGroupID, PublisherIdentityID, DeploymentID, ReplicaKey)
	metrics.ingressOperations = newHistogram(m, "tnl_ingress_operation_duration_seconds", "Completed ingress operation duration by fixed operation and outcome.", DurationBucketsSeconds(), Operation, OutcomeKey)
	metrics.relayOperations = newHistogram(m, "tnl_relay_operation_duration_seconds", "Completed relay operation duration by fixed operation and outcome.", DurationBucketsSeconds(), Operation, OutcomeKey)
	metrics.relayBytes = newCounter(m, "tnl_relay_forwarded_bytes_total", "Wire bytes copied by relay, including preserved PROXY metadata; recorded at stream close.", ServiceKindKey, Direction)
	metrics.relayCompletions = newCounter(m, "tnl_relay_visitor_stream_completions_total", "Opened visitor streams whose relay copy ended, not application request outcomes.", ServiceKindKey, OutcomeKey)
	metrics.databaseQueryDuration = newHistogram(m, "tnl_database_query_duration_seconds", "Completed request-pool SQL duration observed by the driver, excluding pool acquisition.", DurationBucketsSeconds(), Operation, OutcomeKey)
	metrics.databaseGuardDuration = newHistogram(m, "tnl_database_guard_held_duration_seconds", "Driver-observed interval from successful guard query completion through transaction completion; not exact PostgreSQL lock time.", DurationBucketsSeconds(), Operation, OutcomeKey)
	metrics.databaseAcquireDuration = newHistogram(m, "tnl_database_pool_acquire_duration_seconds", "Time to acquire a request-pool connection, including waits and failed acquisitions.", DurationBucketsSeconds(), OutcomeKey)
	metrics.databaseFailures = newCounter(m, "tnl_database_failures_total", "Request-pool failures by fixed boundary and outcome; acquire has no SQL operation name.", Operation, OutcomeKey)
	metrics.recoveryDuration = newHistogram(m, "tnl_control_public_url_recovery_duration_seconds", "Duration of newly committed public URL recovery observations on this control process.", DurationBucketsSeconds())
	metrics.recoveryPending = newGauge(m, "tnl_ingress_recovery_observations_pending", "Recovery observations awaiting a successful or stale response.")
	metrics.recoveryAttempts = newCounter(m, "tnl_ingress_recovery_observation_attempts_total", "Recovery reporting attempts by bounded outcome.", OutcomeKey)
	metrics.certificateClaims = newCounter(m, "tnl_control_certificate_claims_total", "Certificate worker claims by certificate kind and outcome.", CertificateKind, OutcomeKey)
	metrics.certificateOrders = newCounter(m, "tnl_control_certificate_orders_total", "New service certificate orders committed by this control process, excluding idempotent retries and certificate reuse; not a CA issuance quota.", CertificateKind, domainKind, certificatePlan)
	metrics.certificateTransitions = newCounter(m, "tnl_control_certificate_transitions_total", "Committed certificate work transitions by kind and resulting state.", CertificateKind, State)
	metrics.dnsWork = newHistogram(m, "tnl_control_dns_work_duration_seconds", "DNS worker phase duration; count is the number of attempts.", DurationBucketsSeconds(), DNSKind, Operation, OutcomeKey)
	metrics.dnsTransitions = newCounter(m, "tnl_control_dns_transitions_total", "Committed DNS work transitions by kind and resulting state.", DNSKind, State)
	metrics.usageWork = newCounter(m, "tnl_control_public_url_usage_work_total", "Usage worker operations by fixed phase and outcome.", Operation, OutcomeKey)
	metrics.usageItems = newCounter(m, "tnl_control_public_url_usage_items_total", "Usage runs, buckets or deliveries committed by result.", Event)
	metrics.usageReceiverDuration = newHistogram(m, "tnl_control_public_url_usage_receiver_duration_seconds", "Usage receiver request duration by bounded outcome.", DurationBucketsSeconds(), OutcomeKey)
	metrics.usageLastSuccess = newGauge(m, "tnl_control_public_url_usage_last_success_timestamp_seconds", "Unix time of the last successful finalization call or committed delivery; zero before success.", Operation)
	metrics.usageRetained = newGauge(m, "tnl_ingress_usage_retained_buckets", "Ingress usage buckets retained in memory, including dirty and pending buckets.")
	metrics.cleanupRuns = newCounter(m, "tnl_control_cleanup_runs_total", "Cleanup calls by fixed kind and outcome.", CleanupKind, OutcomeKey)
	metrics.cleanupItems = newCounter(m, "tnl_control_cleanup_items_total", "Committed items removed by cleanup kind.", CleanupKind)
	metrics.cleanupLastSuccess = newGauge(m, "tnl_control_cleanup_last_success_timestamp_seconds", "Unix time of last successful cleanup by kind; zero before success.", CleanupKind)
	metrics.registerPortInventory()
	metrics.guestTrialStats = newGauge(m, "tnl_control_guest_trials_last_24h", "Service-wide trial counts from committed state over the last 24 hours; use max rather than sum across control replicas.", Event)
	metrics.placementDecisions = newCounter(m, "tnl_control_placement_decisions_total", "Publish run placement decisions by action and bounded result.", Operation, OutcomeKey)
	metrics.assignmentReplacements = newCounter(m, "tnl_control_connection_assignments_replaced_total", "Committed replacement of connection assignments by fixed reason.", Reason)
	for _, result := range []string{"queued", "delivered", "retry", "dropped", "accepted", "duplicate"} {
		metrics.serviceAudit.With(eventDimension(result)).Add(0)
	}
	if role == RoleControl || role == RoleStandalone {
		metrics.routingHistorySkipped.Add(0)
		metrics.gaugeFunc("tnl_control_routing_history_retained_after_revision", "Highest committed routing-history retention floor observed by this process.", func() float64 { return float64(metrics.routingHistoryFloor.Load()) })
		for _, stage := range []string{"issued", "allocated", "ready", "expired", "ready_limit", "transfer_limit"} {
			metrics.guestTrialStats.With(eventDimension(stage)).Set(0)
		}
		for _, surface := range []string{"control", "authority", "private_ingress", "private_relay"} {
			metrics.apiInFlight.With(Component.Dimension(surface)).Set(0)
		}
		for _, phase := range []operationName{"finalize", "deliver"} {
			metrics.usageLastSuccess.With(Operation.Dimension(phase)).Set(0)
		}
	}
	if role == RoleIngress || role == RoleStandalone {
		metrics.ingressStreams.Set(0)
		metrics.drainingRejections.Add(0)
		metrics.recoveryPending.Set(0)
		metrics.usageRetained.Set(0)
		for _, class := range []string{"client_hello", "public", "denied", "control", "relay_tcp"} {
			metrics.ingressConnections.With(connectionClass.Dimension(class)).Set(0)
		}
	}
	if role == RoleRelay || role == RoleStandalone {
		metrics.publisherConnections.Set(0)
		metrics.registeredConnections.Set(0)
		metrics.relayStreams.Set(0)
		metrics.gaugeFunc("tnl_relay_earliest_lease_expiration_timestamp_seconds", "Earliest known relay lease expiration in this process; zero without a lease.", metrics.earliestRelayLeaseExpiry)
		metrics.gaugeFunc("tnl_relay_transport_certificate_expiration_timestamp_seconds", "Earliest locally known relay transport certificate expiry; zero before material is observed.", metrics.earliestRelayCertificateExpiry)
	}
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
	m.gaugeFunc("tnl_ingress_lease_expiration_timestamp_seconds", "Local ingress lease expiration; zero before registration or after lease loss.", func() float64 { return routingTimestamp(source()) })
}

// RegisterControlCertificate reads certificate material already in this process.
func (m *Metrics) RegisterControlCertificate(source func() time.Time) {
	m.gaugeFunc("tnl_control_tls_certificate_expiration_timestamp_seconds", "Locally loaded internal control certificate expiry. Public control TLS belongs to the deployment proxy.", func() float64 { return routingTimestamp(source()) })
}

// SetGuestTrialStats observes committed service-wide counts without identity labels.
func (m *Metrics) SetGuestTrialStats(issued, allocated, ready, expired, readyLimit, transferLimit int64) {
	for stage, count := range map[string]int64{
		"issued": issued, "allocated": allocated, "ready": ready,
		"expired": expired, "ready_limit": readyLimit, "transfer_limit": transferLimit,
	} {
		if count >= 0 {
			m.guestTrialStats.With(eventDimension(stage)).Set(float64(count))
		}
	}
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(prometheus.Gatherers{m.registry, m.runtimeRegistry}, promhttp.HandlerOpts{})
}

// Gather captures this process's registry using only passive collectors.
func (m *Metrics) Gather() ([]*dto.MetricFamily, error) {
	return (prometheus.Gatherers{m.registry, m.runtimeRegistry}).Gather()
}

func (m *Metrics) SetRelayLeases(state string, count int) {
	if m == nil || state != "active" && state != "draining" {
		return
	}
	m.relayLeases.With(stateDimension(state)).Set(float64(count))
}

func (m *Metrics) AddRelayLeases(state string, delta int) {
	if m == nil || state != "active" && state != "draining" {
		return
	}
	m.relayLeases.With(stateDimension(state)).Add(float64(delta))
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
	m.capacityRejections.With(CapacityResource.Dimension(resource)).Inc()
}

func (m *Metrics) IncDrainingRejection() { m.drainingRejections.Inc() }

func (m *Metrics) SetCapacityLimit(resource string, limit int64) {
	if !admissionResource(resource) || limit < 0 {
		return
	}
	m.capacityLimits.With(CapacityResource.Dimension(resource)).Set(float64(limit))
}

func admissionResource(resource string) bool {
	return slices.Contains(admissionResources, resource)
}

func (m *Metrics) IncInspectionFailure(stage string) {
	switch stage {
	case "deadline", "metadata", "client_hello", "hostname":
		m.inspectionFailures.With(Operation.Dimension(operationName(stage))).Inc()
	}
}

func (m *Metrics) AddForwardedBytes(direction string, count int64) {
	m.forwardedBytes.With(Direction.Dimension(direction)).Add(float64(count))
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
	var dimensions []Dimension
	if slot == "0" {
		dimensions = append(dimensions, ConnectionSlot.Dimension(0))
	}
	if slot == "1" {
		dimensions = append(dimensions, ConnectionSlot.Dimension(1))
	}
	dimensions = append(dimensions, resultDimension(string(outcome)))
	m.relayAttempts.With(dimensions...).Inc()
}

func (m *Metrics) ObserveAPIRequest(surface, operation string, outcome APIRequestOutcome, duration time.Duration) {
	method, route, matched := strings.Cut(operation, " ")
	if !matched {
		method, route = "_OTHER", operation
	}
	m.observeAPIRequest(surface, method, route, outcome, duration)
}

func (m *Metrics) observeAPIRequest(surface, method, route string, outcome APIRequestOutcome, duration time.Duration) {
	m.apiDuration.With(Component.Dimension(surface), HTTPMethod.Dimension(httpMethod(method)), HTTPRoute.Dimension(route), resultDimension(string(outcome))).Observe(duration.Seconds())
}

// outcomes and stages are closed sets, independent of public URL and order identity.
func (m *Metrics) ObservePublishRunReadiness(outcome readiness.Outcome, duration, age time.Duration) {
	switch outcome {
	case readiness.Ready, readiness.CertificateMissing, readiness.ConnectionsMissing,
		readiness.CertificateAndConnectionsMissing, readiness.DNSPending, readiness.DNSFailed, readiness.Error:
	default:
		outcome = readiness.Error
	}
	m.readinessDuration.With(stateDimension(string(outcome))).Observe(duration.Seconds())
	if outcome != readiness.Error && age >= 0 {
		m.readinessAge.With(stateDimension(string(outcome))).Observe(age.Seconds())
	}
}

func (m *Metrics) ObserveCertificateWork(stage string, outcome CertificateWorkOutcome, duration time.Duration) {
	m.ObserveCertificateIteration("public_url", stage, outcome, duration)
}

func (m *Metrics) ObserveCertificateIteration(kind, stage string, outcome CertificateWorkOutcome, duration time.Duration) {
	m.ObserveCertificateIterationContext(context.Background(), kind, stage, outcome, duration)
}

func (m *Metrics) ObserveCertificateIterationContext(ctx context.Context, kind, stage string, outcome CertificateWorkOutcome, duration time.Duration) {
	if m == nil || kind != "public_url" && kind != "relay" && kind != "service" {
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
	ctx, finish := m.completedResult(ctx, operationName("certificate."+kind+"."+stage), string(outcome), duration)
	trace.SpanFromContext(ctx).SetAttributes(CertificateKind.String(kind), Operation.Value(operationName(stage)))
	m.certificateDuration.With(CertificateKind.Dimension(kind), Operation.Dimension(operationName(stage)), resultDimension(string(outcome))).ObserveContext(ctx, duration.Seconds())
	finish()
}

func (m *Metrics) ObserveCertificateMilestone(kind, milestone string, age time.Duration) {
	if m == nil || kind != "public_url" && kind != "service" || milestone != "ready" && milestone != "cleanup" || age < 0 {
		return
	}
	m.certificateMilestone.With(CertificateKind.Dimension(kind), eventDimension(milestone)).Observe(age.Seconds())
}
