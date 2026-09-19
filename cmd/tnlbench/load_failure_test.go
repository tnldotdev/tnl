package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoadCapturesFirstVisitorFailureBeforeNextRequest(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var visitors, diagnostics, metrics atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			visitors.Add(1)
			_ = connection.Close()
		}
	}()
	defer func() { _ = listener.Close(); <-done }()
	observability := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/debug/database" {
			diagnostics.Add(1)
			if visitors.Load() != 1 {
				t.Errorf("capture after %d visitor attempts", visitors.Load())
			}
			_, _ = w.Write([]byte(`{"active_operations":[{"operation":"LockRouteSessionForUsage","elapsed_seconds":12}],"error":"upstream visibility unavailable"}`))
		} else {
			metrics.Add(1)
			_, _ = w.Write([]byte("tnl_database_pool_acquired_connections 4\n"))
		}
	}))
	defer observability.Close()
	state := newCoordinatorState("failure", 1, 1, 2)
	server := httptest.NewServer(coordinatorHandler("secret", state))
	defer server.Close()
	client, err := newCoordinatorClient(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.publisherReady(t.Context(), 0, []benchmarkRouteRegistration{{Index: 0, Hostname: "first.example"}, {Index: 1, Hostname: "second.example"}}); err != nil {
		t.Fatal(err)
	}
	command := loadCommand{
		workerCommand: workerCommand{CellID: "failure", Suite: "scout", Axis: "active_routes", Repetition: 1, WorkerCount: 1, CoordinatorURL: server.URL, CoordinatorToken: "secret"},
		Routes:        2, PublicAddress: listener.Addr().String(), PayloadBytes: 4, Timeout: time.Second,
		MetricsURLs: []string{observability.URL + "/metrics#control"}, DiagnosticURLs: []string{observability.URL + "/debug/database"},
	}
	if err := command.run(t.Context()); err == nil {
		t.Fatal("expected visitor failure")
	}
	if diagnostics.Load() != 1 || metrics.Load() != 1 || visitors.Load() != 2 {
		t.Fatalf("visitors=%d diagnostics=%d metrics=%d", visitors.Load(), diagnostics.Load(), metrics.Load())
	}
	data, err := coordinatorResults(t.Context(), client, true)
	if err != nil {
		t.Fatal(err)
	}
	var result benchmarkResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.DatabaseDiagnostics) != 1 || len(result.DatabaseDiagnostics[0].Snapshot.ActiveOperations) != 1 || len(result.Resources) != 1 || result.Resources[0].Moment != "failure" {
		t.Fatalf("failure snapshot missing: %+v", result)
	}
}

func TestFailureDiagnosticsBoundEndpointsAndRetainLocalActivity(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"error":"upstream unavailable","active_operations":[{"operation":"RenewIngress","elapsed_seconds":1}]}`))
	}))
	defer server.Close()
	endpoints := make([]string, 100)
	for index := range endpoints {
		endpoints[index] = server.URL
	}
	snapshots := sampleDatabaseDiagnostics(t.Context(), endpoints)
	if calls.Load() != 8 || len(snapshots) != 8 {
		t.Fatal("unbounded diagnostic endpoints")
	}
	for _, snapshot := range snapshots {
		if snapshot.Error != "upstream unavailable" || len(snapshot.Snapshot.ActiveOperations) != 1 {
			t.Fatal("lost local activity on upstream error")
		}
	}
}
