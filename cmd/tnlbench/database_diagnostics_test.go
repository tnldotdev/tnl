package main

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

func TestDatabaseDiagnosticMaximumShapeRoundTrip(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 999999999, time.UTC)
	age, queryID := math.MaxFloat64, int64(math.MinInt64)
	snapshot := controlstate.DatabaseDiagnostics{CapturedAt: now, Truncated: true, OperationsTruncated: true}
	snapshot.Connections = make(map[string]controlstate.DatabaseConnectionCounts)
	for _, purpose := range []string{"request_pool", "tls_leadership", "dns_challenge", "diagnostics", "pooler_diagnostics"} {
		snapshot.Connections[purpose] = controlstate.DatabaseConnectionCounts{
			Open: math.MaxInt64, Connecting: math.MaxInt64, Opened: math.MaxInt64, Closed: math.MaxInt64, Failed: math.MaxInt64,
		}
	}
	snapshot.Pooler = &controlstate.DatabasePoolerDiagnostics{
		Settings: map[string]string{"pool_mode": "transaction"},
		Clients:  &controlstate.DatabasePoolerClients{Total: 4096, Active: 4096, Waiting: 4096, Other: 4096, Truncated: true},
		Error:    strings.Repeat("x", 160),
	}
	for _, key := range []string{"max_client_conn", "default_pool_size", "reserve_pool_size", "max_db_connections", "max_user_connections", "server_lifetime", "client_idle_timeout"} {
		snapshot.Pooler.Settings[key] = "4294967295"
	}
	for index := range controlstate.MaxDatabaseDiagnosticSessions {
		session := controlstate.DatabaseSession{
			PID: math.MaxInt32, Operation: strings.Repeat("Q", 128),
			State: "idle in transaction (aborted)", WaitType: "Extension", WaitEvent: strings.Repeat("W", 63),
			TransactionAgeSeconds: &age, QueryAgeSeconds: &age, QueryID: &queryID,
			BlockingPIDsTruncated: index%2 == 0,
		}
		for blocker := range controlstate.MaxDatabaseDiagnosticBlockers {
			session.BlockingPIDs = append(session.BlockingPIDs, math.MaxInt32-int32(blocker))
		}
		snapshot.Sessions = append(snapshot.Sessions, session)
	}
	for range controlstate.MaxDatabaseDiagnosticOperations {
		snapshot.ActiveOperations = append(snapshot.ActiveOperations, controlstate.DatabaseOperation{Operation: strings.Repeat("Q", 128), ElapsedSeconds: age})
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded)+1 > controlstate.MaxDatabaseDiagnosticBytes {
		t.Fatalf("allowed snapshot needs %d bytes; reader allows %d", len(encoded)+1, controlstate.MaxDatabaseDiagnosticBytes)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(snapshot); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	endpoints := make([]string, 8)
	for index := range endpoints {
		endpoints[index] = server.URL
	}
	diagnostics := sampleDatabaseDiagnostics(t.Context(), endpoints)
	if len(diagnostics) != len(endpoints) {
		t.Fatal("collector dropped snapshots")
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Error != "" || diagnostic.Snapshot == nil || !reflect.DeepEqual(*diagnostic.Snapshot, snapshot) {
			t.Fatalf("maximum-shaped snapshot lost operations or truncation markers: error=%q", diagnostic.Error)
		}
	}
	// Keep the existing 2 MiB coordinator budget: eight maximum-shaped snapshots
	// fit alongside the periodic window, both boundaries, and a failure snapshot.
	result := passedTestResult(resultWorker{Kind: "load", Index: 0, Count: 1})
	result.DatabaseDiagnostics = diagnostics
	for _, budget := range []int{512 << 10, 192 << 10, 192 << 10, 192 << 10} {
		sample := resourceSample{Role: "control", Identity: "control.internal", Moment: "failure", Timestamp: now,
			Metrics: metricsForTest("tnl_" + strings.Repeat("x", budget-1024) + " 1\n"),
		}
		encodedSample, err := json.Marshal(sample)
		if err != nil || len(encodedSample) > budget {
			t.Fatalf("metric window fixture exceeds budget: %d, %v", len(encodedSample), err)
		}
		result.Resources = append(result.Resources, sample)
	}
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > 2<<20 {
		t.Fatalf("failure result exceeds coordinator budget: %d bytes", len(body))
	}
	coordinator := httptest.NewServer(coordinatorHandler("secret", newCoordinatorState("cell-1", 1, 1, 1)))
	defer coordinator.Close()
	client, err := newCoordinatorClient(coordinator.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.postResult(t.Context(), result); err != nil {
		t.Fatalf("coordinator rejected maximum-shaped failure diagnostics: %v", err)
	}
	t.Logf("maximum snapshot: %d bytes; result with eight snapshots and metrics windows: %d of %d bytes", len(encoded)+1, len(body), 2<<20)
}
