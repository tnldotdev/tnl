package observability

import (
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDatabaseMetricsUseOnePassiveSnapshot(t *testing.T) {
	config, err := pgxpool.ParseConfig("postgres://postgres@127.0.0.1:1/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 3
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	metrics := New("control")
	var calls atomic.Int64
	metrics.RegisterDatabase(func(time.Time) DatabaseSnapshot {
		calls.Add(1)
		return DatabaseSnapshot{
			Pool: pool.Stat(),
			Connections: map[string]DatabaseConnectionSnapshot{
				"request_pool": {Open: 2, Connecting: 1, Opened: 5, Closed: 3, Failed: 4},
			},
			ActiveOperations: []DatabaseOperationSnapshot{
				{Operation: "HeartbeatRouteSession", ElapsedSeconds: 2},
				{Operation: "HeartbeatRouteSession", ElapsedSeconds: 7},
				{Operation: "unknown", ElapsedSeconds: 3},
			},
			OperationsOmitted: 6,
		}
	})
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	if calls.Load() != 1 {
		t.Fatalf("database snapshots = %d, want 1", calls.Load())
	}
	text := response.Body.String()
	for _, want := range []string{
		`tnl_database_pool_max_connections 3`,
		`tnl_database_pool_total_connections 0`,
		`tnl_database_client_connections{purpose="request_pool",state="open"} 2`,
		`tnl_database_client_connections{purpose="request_pool",state="connecting"} 1`,
		`tnl_database_client_connection_events_total{event="opened",purpose="request_pool"} 5`,
		`tnl_database_client_connection_events_total{event="closed",purpose="request_pool"} 3`,
		`tnl_database_client_connection_events_total{event="failed",purpose="request_pool"} 4`,
		`tnl_database_operations_active{operation="HeartbeatRouteSession"} 2`,
		`tnl_database_operation_oldest_age_seconds{operation="HeartbeatRouteSession"} 7`,
		`tnl_database_operations_active{operation="unknown"} 1`,
		`tnl_database_operations_omitted 6`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q:\n%s", want, text)
		}
	}
}
