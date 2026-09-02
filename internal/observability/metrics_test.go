package observability

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"modernc.org/sqlite"
)

func TestMetricsScrape(t *testing.T) {
	metrics := New("worker")
	metrics.SetRoutes("active", 7)
	metrics.SetWorkerRoutes(7)
	metrics.SetWorkerCapacity(500)
	metrics.SetWorkerDraining(true)
	metrics.SetStreams(3)
	metrics.SetTailcatPaths("derp", 5)
	metrics.IncTailcatFailure("start", "timeout")
	metrics.AddTailcatForcedCloses(2)
	metrics.IncCapacityRejection("routes")
	metrics.IncSourceLimiterRejection()
	metrics.SetSourceLimiterEntries(17)
	metrics.IncIPAllowlistDenial()
	metrics.SetFriendlyNameCapacity(100, 90)
	metrics.AddForwardedBytes("ingress", 1024)
	metrics.ObserveAPIRequest("routes.create", "success", 10*time.Second)
	metrics.ObserveSQLiteOperation("route_create", 5*time.Second, nil)
	metrics.ObserveRouteCoordinatorStage("heartbeat_route_lock_wait", 10*time.Second)
	metrics.ObserveRouteSessionHeartbeat("success")
	metrics.ObserveRouteRemoval("session_expired")
	metrics.SetRouteSessionMinSecondsRemaining("active", 17.5)
	metrics.SetWorkersConnected(4)
	metrics.ObserveWorkerSessionEstablished("edge")
	metrics.ObserveWorkerSessionEstablished("edge")
	metrics.ObserveWorkerSessionDisconnected("edge", "network")
	metrics.SetRouteUsageOutbox("usage", 3)
	metrics.SetRouteUsageOutbox("registration", 2)
	metrics.SetRouteUsageOldestAge(12 * time.Second)
	metrics.ObserveRouteUsageCheckpoint("success")
	metrics.ObserveRouteUsageDelivery("usage", "error")
	metrics.ObserveRouteUsageDelivery("registration", "success")

	body := scrape(t, metrics)
	for _, line := range []string{
		`tnl_info{mode="worker"} 1`,
		`tnl_routes{status="active"} 7`,
		`tnl_worker_routes_active 7`,
		`tnl_worker_route_capacity 500`,
		`tnl_worker_draining 1`,
		`tnl_streams_active 3`,
		`tnl_tailcat_paths{path="derp"} 5`,
		`tnl_tailcat_failures_total{operation="start",reason="timeout"} 1`,
		`tnl_tailcat_forced_closes_total 2`,
		`tnl_capacity_rejections_total{resource="routes"} 1`,
		`tnl_source_limiter_rejections_total 1`,
		`tnl_source_limiter_entries 17`,
		`tnl_ip_allowlist_denials_total 1`,
		`tnl_friendly_name_namespace_capacity 100`,
		`tnl_friendly_name_namespace_remaining_lower_bound 90`,
		`tnl_forwarded_bytes_total{direction="ingress"} 1024`,
		`tnl_api_requests_total{operation="routes.create",result="success"} 1`,
		`tnl_api_request_duration_seconds_bucket{operation="routes.create",le="10"} 1`,
		`tnl_api_request_duration_seconds_count{operation="routes.create"} 1`,
		`tnl_api_request_duration_seconds_sum{operation="routes.create"} 10`,
		`tnl_sqlite_operation_duration_seconds_bucket{operation="route_create",le="5"} 1`,
		`tnl_sqlite_operation_duration_seconds_count{operation="route_create"} 1`,
		`tnl_sqlite_operation_duration_seconds_sum{operation="route_create"} 5`,
		`tnl_route_coordinator_stage_duration_seconds_bucket{stage="heartbeat_route_lock_wait",le="10"} 1`,
		`tnl_route_coordinator_stage_duration_seconds_count{stage="heartbeat_route_lock_wait"} 1`,
		`tnl_route_coordinator_stage_duration_seconds_sum{stage="heartbeat_route_lock_wait"} 10`,
		`tnl_route_session_heartbeats_total{result="success"} 1`,
		`tnl_route_removals_total{reason="session_expired"} 1`,
		`tnl_route_session_min_seconds_remaining{status="active"} 17.5`,
		`tnl_workers_connected 4`,
		`tnl_worker_sessions_active{role="edge"} 1`,
		`tnl_worker_session_establishments_total{role="edge"} 2`,
		`tnl_worker_session_disconnects_total{reason="network",role="edge"} 1`,
		`tnl_route_usage_outbox_items{kind="usage"} 3`,
		`tnl_route_usage_outbox_items{kind="registration"} 2`,
		`tnl_route_usage_oldest_item_age_seconds 12`,
		`tnl_route_usage_checkpoints_total{result="success"} 1`,
		`tnl_route_usage_deliveries_total{kind="usage",result="error"} 1`,
		`tnl_route_usage_deliveries_total{kind="registration",result="success"} 1`,
	} {
		if !strings.Contains(body, line) {
			t.Errorf("scrape does not contain %q", line)
		}
	}
	for _, family := range []string{"process_open_fds", "process_max_fds"} {
		if count := strings.Count(body, "# HELP "+family+" "); count != 1 {
			t.Errorf("scrape contains %d HELP entries for %s, want 1", count, family)
		}
	}
}

func TestRegisterDatabase(t *testing.T) {
	metrics := New("server")
	if err := metrics.RegisterDatabase(nil); err == nil {
		t.Fatal("RegisterDatabase(nil) succeeded")
	}

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	db.SetMaxOpenConns(7)
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
	if err := metrics.RegisterDatabase(db); err != nil {
		t.Fatal(err)
	}
	if err := metrics.RegisterDatabase(db); err == nil {
		t.Fatal("duplicate RegisterDatabase succeeded")
	}

	connection, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	active := scrape(t, metrics)
	for _, line := range []string{
		`tnl_sqlite_pool_connections{state="open"} 1`,
		`tnl_sqlite_pool_connections{state="in_use"} 1`,
		`tnl_sqlite_pool_connections{state="idle"} 0`,
		`tnl_sqlite_pool_connection_limit 7`,
		`tnl_sqlite_pool_waits_total 0`,
		`tnl_sqlite_pool_wait_seconds_total 0`,
	} {
		if !strings.Contains(active, line) {
			t.Errorf("active scrape does not contain %q", line)
		}
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	idle := scrape(t, metrics)
	for _, line := range []string{
		`tnl_sqlite_pool_connections{state="in_use"} 0`,
		`tnl_sqlite_pool_connections{state="idle"} 1`,
	} {
		if !strings.Contains(idle, line) {
			t.Errorf("idle scrape does not contain %q", line)
		}
	}
}

func TestSQLiteErrorClassification(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	if _, err := db.Exec(`CREATE TABLE records (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO records (id) VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	_, constraintErr := db.Exec(`INSERT INTO records (id) VALUES (1)`)
	var concrete *sqlite.Error
	if !errors.As(constraintErr, &concrete) {
		t.Fatalf("constraint error type = %T, want wrapped *sqlite.Error", constraintErr)
	}
	_, syntaxErr := db.Exec(`NOT SQL`)
	if !errors.As(syntaxErr, &concrete) {
		t.Fatalf("syntax error type = %T, want wrapped *sqlite.Error", syntaxErr)
	}

	metrics := New("server")
	metrics.ObserveSQLiteOperation("canceled", time.Millisecond, fmt.Errorf("query: %w", context.Canceled))
	metrics.ObserveSQLiteOperation("deadline", time.Millisecond, fmt.Errorf("query: %w", context.DeadlineExceeded))
	metrics.ObserveSQLiteOperation("constraint", time.Millisecond, fmt.Errorf("insert: %w", constraintErr))
	metrics.ObserveSQLiteOperation("other", time.Millisecond, fmt.Errorf("query: %w", syntaxErr))
	metrics.ObserveSQLiteOperation("domain", time.Millisecond, errors.New("name unavailable"))
	metrics.ObserveSQLiteOperation("missing", time.Millisecond, fmt.Errorf("query: %w", sql.ErrNoRows))
	metrics.ObserveSQLiteOperation("fake", time.Millisecond, codedError(5))
	metrics.ObserveSQLiteOperation("success", time.Millisecond, nil)

	body := scrape(t, metrics)
	for _, line := range []string{
		`tnl_sqlite_errors_total{operation="canceled",reason="canceled"} 1`,
		`tnl_sqlite_errors_total{operation="deadline",reason="deadline"} 1`,
		`tnl_sqlite_errors_total{operation="constraint",reason="constraint"} 1`,
		`tnl_sqlite_errors_total{operation="other",reason="other"} 1`,
	} {
		if !strings.Contains(body, line) {
			t.Errorf("scrape does not contain %q", line)
		}
	}
	for _, operation := range []string{"domain", "missing", "fake", "success"} {
		if strings.Contains(body, `tnl_sqlite_errors_total{operation="`+operation+`"`) {
			t.Errorf("scrape unexpectedly classifies operation %q", operation)
		}
	}
	if count := strings.Count(body, "tnl_sqlite_errors_total{"); count != 4 {
		t.Errorf("scrape contains %d SQLite error series, want 4", count)
	}
}

func TestSQLitePrimaryReason(t *testing.T) {
	for _, test := range []struct {
		code int
		want string
	}{
		{5, "busy"},
		{6 | 1<<8, "locked"},
		{10 | 8<<8, "io"},
		{11, "corrupt"},
		{19 | 6<<8, "constraint"},
		{1, "other"},
	} {
		if got := sqlitePrimaryReason(test.code); got != test.want {
			t.Errorf("sqlitePrimaryReason(%d) = %q, want %q", test.code, got, test.want)
		}
	}
}

type codedError int

func (e codedError) Error() string { return "coded error" }
func (e codedError) Code() int     { return int(e) }

func scrape(t *testing.T, metrics *Metrics) string {
	t.Helper()
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("scrape status = %d, want %d", response.Code, http.StatusOK)
	}
	body, err := io.ReadAll(response.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
