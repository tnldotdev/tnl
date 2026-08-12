package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCoordinatorReleasesPhasesAndOrdersResults(t *testing.T) {
	state := newCoordinatorState("cell-1", 2, 1, 2)
	server := httptest.NewServer(coordinatorHandler("secret", state))
	defer server.Close()
	client, err := newCoordinatorClient(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- client.waitPublishers(t.Context()) }()
	if err := client.publisherReady(t.Context(), 0, []benchmarkRouteRegistration{{Index: 0, Hostname: "first.example.com"}}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-wait:
		t.Fatalf("publisher wait returned early: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	if err := client.publisherReady(t.Context(), 1, []benchmarkRouteRegistration{{Index: 1, Hostname: "second.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := <-wait; err != nil {
		t.Fatal(err)
	}
	routes, err := client.routes(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 || routes[0] != "first.example.com" || routes[1] != "second.example.com" {
		t.Fatalf("routes = %v", routes)
	}
	for _, worker := range []resultWorker{{Kind: "load", Index: 0, Count: 1}, {Kind: "publisher", Index: 1, Count: 2}, {Kind: "publisher", Index: 0, Count: 2}} {
		if err := client.postResult(t.Context(), passedTestResult(worker)); err != nil {
			t.Fatal(err)
		}
	}
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/v1/results", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(response.Body)
	var got []string
	for {
		var result benchmarkResult
		if err := decoder.Decode(&result); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		got = append(got, result.Worker.Kind)
	}
	if response.StatusCode != http.StatusOK || !bytes.Equal([]byte(got[0]+got[1]+got[2]), []byte("publisherpublisherload")) {
		t.Fatalf("status = %d, order = %v", response.StatusCode, got)
	}
}

func TestCoordinatorFailureAbortsWait(t *testing.T) {
	state := newCoordinatorState("cell-1", 1, 1, 1)
	server := httptest.NewServer(coordinatorHandler("secret", state))
	defer server.Close()
	client, _ := newCoordinatorClient(server.URL, "secret")
	result := passedTestResult(resultWorker{Kind: "load", Index: 0, Count: 1})
	result.Status = "failed"
	result.Failure = &resultFailure{Message: strings.Repeat("saturated ", coordinatorStatusFailureLimit)}
	if err := client.postResult(t.Context(), result); err != nil {
		t.Fatal(err)
	}
	if err := client.waitPublishers(context.Background()); err == nil {
		t.Fatal("aborted publisher wait succeeded")
	} else if len(err.Error()) > coordinatorStatusFailureLimit+128 {
		t.Fatalf("publisher wait error is unexpectedly long: %d bytes", len(err.Error()))
	}
	state.mu.Lock()
	stored := state.results["load:0"].Failure.Message
	state.mu.Unlock()
	if len(stored) > coordinatorStatusFailureLimit+len("\n[truncated]") || !strings.HasSuffix(stored, "\n[truncated]") {
		t.Fatalf("stored failure length = %d", len(stored))
	}
}

func TestCoordinatorRejectsConflictingRouteRegistration(t *testing.T) {
	state := newCoordinatorState("cell-1", 2, 1, 2)
	server := httptest.NewServer(coordinatorHandler("secret", state))
	defer server.Close()
	client, _ := newCoordinatorClient(server.URL, "secret")
	if err := client.publisherReady(t.Context(), 0, []benchmarkRouteRegistration{{Index: 0, Hostname: "route.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := client.publisherReady(t.Context(), 1, []benchmarkRouteRegistration{{Index: 0, Hostname: "other.example.com"}}); err == nil {
		t.Fatal("conflicting route registration succeeded")
	}
}

func TestCoordinatorStatusBoundsFailure(t *testing.T) {
	state := newCoordinatorState("cell-1", 1, 1, 1)
	state.failure = strings.Repeat("failure ", coordinatorStatusFailureLimit)
	status := state.statusLocked()
	if len(status.Failure) > coordinatorStatusFailureLimit+len("\n[truncated]") || !strings.HasSuffix(status.Failure, "\n[truncated]") {
		t.Fatalf("bounded failure length = %d, suffix = %q", len(status.Failure), status.Failure[len(status.Failure)-16:])
	}
}

func passedTestResult(worker resultWorker) benchmarkResult {
	return benchmarkResult{
		SchemaVersion: benchmarkResultSchemaVersion, CellID: "cell-1", Status: "passed", Suite: "smoke",
		Repetition: 1, Worker: worker,
	}
}
