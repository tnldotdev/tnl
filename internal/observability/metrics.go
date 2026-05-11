package observability

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"modernc.org/sqlite"
)

// Metrics owns a process-local Prometheus registry.
type Metrics struct {
	registry              *prometheus.Registry
	routes                *prometheus.GaugeVec
	workerRoutes          prometheus.Gauge
	workerCapacity        prometheus.Gauge
	workerDraining        prometheus.Gauge
	streams               prometheus.Gauge
	tailcatPaths          *prometheus.GaugeVec
	tailcatFailures       *prometheus.CounterVec
	tailcatForcedClose    prometheus.Counter
	capacityRejections    *prometheus.CounterVec
	sourceLimiterRejects  prometheus.Counter
	sourceLimiterEntries  prometheus.Gauge
	ipAllowlistDenials    prometheus.Counter
	nameCapacity          prometheus.Gauge
	nameRemaining         prometheus.Gauge
	forwardedBytes        *prometheus.CounterVec
	apiRequests           *prometheus.CounterVec
	apiRequestDuration    *prometheus.HistogramVec
	sqliteDuration        *prometheus.HistogramVec
	sqliteErrors          *prometheus.CounterVec
	coordinatorStage      *prometheus.HistogramVec
	routeHeartbeats       *prometheus.CounterVec
	routeRemovals         *prometheus.CounterVec
	routeSessionMinimum   *prometheus.GaugeVec
	workersConnected      prometheus.Gauge
	workerSessions        *prometheus.GaugeVec
	sessionStarts         *prometheus.CounterVec
	sessionDisconnects    *prometheus.CounterVec
	routeUsageOutbox      *prometheus.GaugeVec
	routeUsageOldestAge   prometheus.Gauge
	routeUsageCheckpoints *prometheus.CounterVec
	routeUsageDeliveries  *prometheus.CounterVec
}

// New constructs an isolated registry for one process role.
func New(mode string) *Metrics {
	registry := prometheus.NewRegistry()
	info := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "tnl_info",
		Help:        "Information about the running tnl process.",
		ConstLabels: prometheus.Labels{"mode": mode},
	})
	info.Set(1)
	metrics := &Metrics{
		registry: registry,
		routes: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tnl_routes",
			Help: "Current routes by lifecycle status.",
		}, []string{"status"}),
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
		sourceLimiterRejects: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tnl_source_limiter_rejections_total",
			Help: "Public connection starts rejected by per-source limiting.",
		}),
		sourceLimiterEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tnl_source_limiter_entries",
			Help: "Current bounded per-source limiter entries.",
		}),
		ipAllowlistDenials: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tnl_ip_allowlist_denials_total",
			Help: "Public route connections denied by IP allowlists.",
		}),
		nameCapacity: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tnl_friendly_name_namespace_capacity",
			Help: "Total usable friendly-name pairs in the reviewed corpus.",
		}),
		nameRemaining: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tnl_friendly_name_namespace_remaining_lower_bound",
			Help: "Conservative lower bound of friendly-name pairs not present in the name ledger.",
		}),
		forwardedBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_forwarded_bytes_total",
			Help: "Bytes forwarded by direction.",
		}, []string{"direction"}),
		apiRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_api_requests_total",
			Help: "Completed API requests by operation and result.",
		}, []string{"operation", "result"}),
		apiRequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "tnl_api_request_duration_seconds",
			Help:    "API request duration by operation.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}, []string{"operation"}),
		sqliteDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "tnl_sqlite_operation_duration_seconds",
			Help:    "SQLite operation duration by operation.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		}, []string{"operation"}),
		sqliteErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_sqlite_errors_total",
			Help: "SQLite and database-context errors by operation and stable reason.",
		}, []string{"operation", "reason"}),
		coordinatorStage: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "tnl_route_coordinator_stage_duration_seconds",
			Help:    "Route coordinator duration by bounded internal stage.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}, []string{"stage"}),
		routeHeartbeats: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_route_session_heartbeats_total",
			Help: "Route session heartbeat attempts by result.",
		}, []string{"result"}),
		routeRemovals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_route_removals_total",
			Help: "Route removals by reason.",
		}, []string{"reason"}),
		routeSessionMinimum: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tnl_route_session_min_seconds_remaining",
			Help: "Minimum seconds remaining on a route session by lifecycle status.",
		}, []string{"status"}),
		workersConnected: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tnl_workers_connected",
			Help: "Current connected route workers.",
		}),
		workerSessions: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tnl_worker_sessions_active",
			Help: "Current established worker sessions by endpoint role.",
		}, []string{"role"}),
		sessionStarts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_worker_session_establishments_total",
			Help: "Established worker sessions by endpoint role.",
		}, []string{"role"}),
		sessionDisconnects: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_worker_session_disconnects_total",
			Help: "Disconnected worker sessions by endpoint role and reason.",
		}, []string{"role", "reason"}),
		routeUsageOutbox: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "tnl_route_usage_outbox_items",
			Help: "Current queued route usage items by bounded kind.",
		}, []string{"kind"}),
		routeUsageOldestAge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tnl_route_usage_oldest_item_age_seconds",
			Help: "Age in seconds of the oldest queued route usage item.",
		}),
		routeUsageCheckpoints: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_route_usage_checkpoints_total",
			Help: "Route usage checkpoints by result.",
		}, []string{"result"}),
		routeUsageDeliveries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tnl_route_usage_deliveries_total",
			Help: "Route usage delivery attempts by bounded kind and result.",
		}, []string{"kind", "result"}),
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
		metrics.sourceLimiterRejects,
		metrics.sourceLimiterEntries,
		metrics.ipAllowlistDenials,
		metrics.nameCapacity,
		metrics.nameRemaining,
		metrics.forwardedBytes,
		metrics.apiRequests,
		metrics.apiRequestDuration,
		metrics.sqliteDuration,
		metrics.sqliteErrors,
		metrics.coordinatorStage,
		metrics.routeHeartbeats,
		metrics.routeRemovals,
		metrics.routeSessionMinimum,
		metrics.workersConnected,
		metrics.workerSessions,
		metrics.sessionStarts,
		metrics.sessionDisconnects,
		metrics.routeUsageOutbox,
		metrics.routeUsageOldestAge,
		metrics.routeUsageCheckpoints,
		metrics.routeUsageDeliveries,
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

// SetRoutes records the authoritative route count for a lifecycle status.
func (m *Metrics) SetRoutes(status string, count int) {
	m.routes.WithLabelValues(status).Set(float64(count))
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

func (m *Metrics) IncSourceLimiterRejection() {
	m.sourceLimiterRejects.Inc()
}

func (m *Metrics) SetSourceLimiterEntries(entries int) {
	m.sourceLimiterEntries.Set(float64(entries))
}

func (m *Metrics) IncIPAllowlistDenial() {
	m.ipAllowlistDenials.Inc()
}

// SetFriendlyNameCapacity records total and conservatively remaining allocator capacity.
func (m *Metrics) SetFriendlyNameCapacity(total, remaining int64) {
	m.nameCapacity.Set(float64(total))
	m.nameRemaining.Set(float64(remaining))
}

// AddForwardedBytes records bytes forwarded in a stable direction.
func (m *Metrics) AddForwardedBytes(direction string, count int64) {
	m.forwardedBytes.WithLabelValues(direction).Add(float64(count))
}

// SetRouteUsageOutbox records queued report items for a bounded source kind.
func (m *Metrics) SetRouteUsageOutbox(kind string, count int64) {
	m.routeUsageOutbox.WithLabelValues(kind).Set(float64(count))
}

// SetRouteUsageOldestAge records the age of the oldest queued report item.
func (m *Metrics) SetRouteUsageOldestAge(age time.Duration) {
	m.routeUsageOldestAge.Set(age.Seconds())
}

// ObserveRouteUsageCheckpoint records a usage checkpoint result.
func (m *Metrics) ObserveRouteUsageCheckpoint(result string) {
	m.routeUsageCheckpoints.WithLabelValues(result).Inc()
}

// ObserveRouteUsageDelivery records a delivery result for a bounded source kind.
func (m *Metrics) ObserveRouteUsageDelivery(kind, result string) {
	m.routeUsageDeliveries.WithLabelValues(kind, result).Inc()
}

// ObserveAPIRequest records a completed request. Operation and result must be bounded producer values.
func (m *Metrics) ObserveAPIRequest(operation, result string, duration time.Duration) {
	m.apiRequests.WithLabelValues(operation, result).Inc()
	m.apiRequestDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// ObserveSQLiteOperation records database latency and classified failures. Operation must be a bounded producer value.
func (m *Metrics) ObserveSQLiteOperation(operation string, duration time.Duration, err error) {
	m.sqliteDuration.WithLabelValues(operation).Observe(duration.Seconds())
	if reason, ok := sqliteErrorReason(err); ok {
		m.sqliteErrors.WithLabelValues(operation, reason).Inc()
	}
}

// ObserveRouteCoordinatorStage records a bounded coordinator stage duration.
func (m *Metrics) ObserveRouteCoordinatorStage(stage string, duration time.Duration) {
	m.coordinatorStage.WithLabelValues(stage).Observe(duration.Seconds())
}

func sqliteErrorReason(err error) (string, bool) {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled", true
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline", true
	}
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) {
		return "", false
	}
	return sqlitePrimaryReason(sqliteErr.Code()), true
}

func sqlitePrimaryReason(code int) string {
	switch code & 0xff {
	case 5:
		return "busy"
	case 6:
		return "locked"
	case 10:
		return "io"
	case 11:
		return "corrupt"
	case 19:
		return "constraint"
	default:
		return "other"
	}
}

// RegisterDatabase adds scrape-time pool metrics for db.
func (m *Metrics) RegisterDatabase(db *sql.DB) error {
	if db == nil {
		return errors.New("observability: nil database")
	}
	if err := m.registry.Register(newDatabaseCollector(db)); err != nil {
		return fmt.Errorf("observability: register database metrics: %w", err)
	}
	return nil
}

// ObserveRouteSessionHeartbeat records a heartbeat result from a bounded producer value.
func (m *Metrics) ObserveRouteSessionHeartbeat(result string) {
	m.routeHeartbeats.WithLabelValues(result).Inc()
}

// ObserveRouteRemoval records a removal reason from a bounded producer value.
func (m *Metrics) ObserveRouteRemoval(reason string) {
	m.routeRemovals.WithLabelValues(reason).Inc()
}

// SetRouteSessionMinSecondsRemaining records a lifecycle status from a bounded producer value.
func (m *Metrics) SetRouteSessionMinSecondsRemaining(status string, seconds float64) {
	m.routeSessionMinimum.WithLabelValues(status).Set(seconds)
}

// SetWorkersConnected records the number of route workers connected to the coordinator.
func (m *Metrics) SetWorkersConnected(count int) {
	m.workersConnected.Set(float64(count))
}

// ObserveWorkerSessionEstablished records an endpoint role from a bounded producer value.
func (m *Metrics) ObserveWorkerSessionEstablished(role string) {
	m.workerSessions.WithLabelValues(role).Inc()
	m.sessionStarts.WithLabelValues(role).Inc()
}

// ObserveWorkerSessionDisconnected records bounded endpoint role and reason values.
func (m *Metrics) ObserveWorkerSessionDisconnected(role, reason string) {
	m.workerSessions.WithLabelValues(role).Dec()
	m.sessionDisconnects.WithLabelValues(role, reason).Inc()
}

type databaseCollector struct {
	db              *sql.DB
	connections     *prometheus.Desc
	connectionLimit *prometheus.Desc
	waits           *prometheus.Desc
	waitSeconds     *prometheus.Desc
}

func newDatabaseCollector(db *sql.DB) *databaseCollector {
	return &databaseCollector{
		db: db,
		connections: prometheus.NewDesc(
			"tnl_sqlite_pool_connections",
			"Current SQLite pool connections by state.",
			[]string{"state"}, nil,
		),
		connectionLimit: prometheus.NewDesc(
			"tnl_sqlite_pool_connection_limit",
			"Maximum number of open SQLite pool connections; zero means unlimited.",
			nil, nil,
		),
		waits: prometheus.NewDesc(
			"tnl_sqlite_pool_waits_total",
			"Total waits for an available SQLite pool connection.",
			nil, nil,
		),
		waitSeconds: prometheus.NewDesc(
			"tnl_sqlite_pool_wait_seconds_total",
			"Total seconds spent waiting for an available SQLite pool connection.",
			nil, nil,
		),
	}
}

func (c *databaseCollector) Describe(descriptions chan<- *prometheus.Desc) {
	descriptions <- c.connections
	descriptions <- c.connectionLimit
	descriptions <- c.waits
	descriptions <- c.waitSeconds
}

func (c *databaseCollector) Collect(metrics chan<- prometheus.Metric) {
	stats := c.db.Stats()
	metrics <- prometheus.MustNewConstMetric(c.connections, prometheus.GaugeValue, float64(stats.OpenConnections), "open")
	metrics <- prometheus.MustNewConstMetric(c.connections, prometheus.GaugeValue, float64(stats.InUse), "in_use")
	metrics <- prometheus.MustNewConstMetric(c.connections, prometheus.GaugeValue, float64(stats.Idle), "idle")
	metrics <- prometheus.MustNewConstMetric(c.connectionLimit, prometheus.GaugeValue, float64(stats.MaxOpenConnections))
	metrics <- prometheus.MustNewConstMetric(c.waits, prometheus.CounterValue, float64(stats.WaitCount))
	metrics <- prometheus.MustNewConstMetric(c.waitSeconds, prometheus.CounterValue, stats.WaitDuration.Seconds())
}
