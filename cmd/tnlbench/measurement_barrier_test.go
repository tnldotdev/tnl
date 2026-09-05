package main

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoadMeasurementBarriersExcludeSetupAndCleanup(t *testing.T) {
	state := newCoordinatorState("barriers", 1, 2, 1)
	server := httptest.NewServer(coordinatorHandler("secret", state))
	defer server.Close()
	client, err := newCoordinatorClient(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := client.loadPhase(ctx, "prepared", 0); err != nil {
		t.Fatal(err)
	}
	if err := client.loadPhase(ctx, "started", 0); err == nil {
		t.Fatal("measurement started before all workers completed setup")
	}
	if err := client.loadPhase(ctx, "prepared", 1); err != nil {
		t.Fatal(err)
	}
	if err := client.waitLoadPhase(ctx, "prepared"); err != nil {
		t.Fatal(err)
	}
	if err := client.loadPhase(ctx, "started", 1); err == nil {
		t.Fatal("non-owner released the baseline scrape barrier")
	}
	if err := client.loadPhase(ctx, "started", 0); err != nil {
		t.Fatal(err)
	}
	if err := client.waitLoadPhase(ctx, "started"); err != nil {
		t.Fatal(err)
	}
	if err := client.loadPhase(ctx, "finished", 0); err != nil {
		t.Fatal(err)
	}
	if err := client.loadPhase(ctx, "collected", 0); err == nil {
		t.Fatal("final scrape completed while another worker was still measuring")
	}
	if err := client.loadPhase(ctx, "finished", 1); err != nil {
		t.Fatal(err)
	}
	if err := client.waitLoadPhase(ctx, "finished"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-state.loadPhaseWait["collected"]:
		t.Fatal("cleanup released before final metrics collection")
	default:
	}
	if err := client.loadPhase(ctx, "collected", 0); err != nil {
		t.Fatal(err)
	}
	if err := client.loadPhase(ctx, "collected", 0); err != nil {
		t.Fatalf("phase retry: %v", err)
	}
	if err := client.waitLoadPhase(ctx, "collected"); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMeasurementBarrierUnblocksOnFailure(t *testing.T) {
	state := newCoordinatorState("barriers", 1, 2, 1)
	server := httptest.NewServer(coordinatorHandler("secret", state))
	defer server.Close()
	client, err := newCoordinatorClient(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := client.postResult(ctx, benchmarkResult{
		SchemaVersion: benchmarkResultSchemaVersion, CellID: "barriers", Status: "failed",
		Worker: resultWorker{Kind: "load", Index: 1, Count: 2}, Failure: &resultFailure{Message: "setup failed", Stage: "setup"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := client.waitLoadPhase(ctx, "prepared"); err == nil || ctx.Err() != nil {
		t.Fatalf("barrier did not report peer failure before its deadline: %v", err)
	}
}
