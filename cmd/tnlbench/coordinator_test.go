package main

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
	"github.com/tnldotdev/tnl/internal/publisher"
)

func passedTestResult(worker resultWorker) benchmarkResult {
	return benchmarkResult{SchemaVersion: benchmarkResultSchemaVersion, CellID: "cell-1", Status: "passed", Worker: worker, Cleanup: resultCleanup{Exact: true}}
}

func TestCoordinatorOwnsRepeatedWindowsAndWaitsForAllParticipants(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	server := httptest.NewServer(benchworkload.NewCoordinator().Handler("token"))
	defer server.Close()
	client, _ := benchworkload.NewCoordination(server.URL, "token")
	c := coordinatorCommand{PublisherWorkers: 1, LoadWorkers: 2, Routes: 1, Repetitions: 2, Duration: time.Millisecond}
	if err := client.Put(ctx, "publisher-0.ready", []benchworkload.PublishedRoute{{Index: 0, Ready: publisher.Event{PublicURL: "https://route.example.test"}}}); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 3)
	go func() {
		err := client.Wait(ctx, "publish.stop", nil)
		if err == nil {
			err = client.Put(ctx, "result.publisher-0", passedTestResult(resultWorker{Kind: "publisher", Count: 1}))
		}
		finished <- err
	}()
	for index := range 2 {
		go func() {
			if err := client.Wait(ctx, "routes", nil); err != nil {
				finished <- err
				return
			}
			if err := client.Put(ctx, fmt.Sprintf("load-%d.ready", index), true); err != nil {
				finished <- err
				return
			}
			for sequence := range 4 {
				var phase benchworkload.Phase
				if err := client.Wait(ctx, fmt.Sprintf("phase-%d", sequence), &phase); err != nil {
					finished <- err
					return
				}
				if sequence == 3 {
					if !phase.Done {
						finished <- fmt.Errorf("missing final barrier")
						return
					}
					break
				}
				if err := client.Put(ctx, fmt.Sprintf("%s.load-%d", phase.Name, index), phaseResult{Name: phase.Name}); err != nil {
					finished <- err
					return
				}
			}
			finished <- client.Put(ctx, fmt.Sprintf("result.load-%d", index), passedTestResult(resultWorker{Kind: "load", Index: index, Count: 2}))
		}()
	}
	rows, err := c.execute(ctx, client)
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	for range 3 {
		if err := <-finished; err != nil {
			t.Fatal(err)
		}
	}
}

func TestCoordinatorRejectsConflictingRoutesAndCollectsPartialFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	server := httptest.NewServer(benchworkload.NewCoordinator().Handler("token"))
	defer server.Close()
	client, _ := benchworkload.NewCoordination(server.URL, "token")
	for i := range 2 {
		_ = client.Put(ctx, fmt.Sprintf("publisher-%d.ready", i), []benchworkload.PublishedRoute{{Index: 0, Ready: publisher.Event{PublicURL: "https://route.example.test"}}})
		_ = client.Put(ctx, fmt.Sprintf("result.publisher-%d", i), passedTestResult(resultWorker{Kind: "publisher", Index: i, Count: 2}))
	}
	_ = client.Put(ctx, "result.load-0", passedTestResult(resultWorker{Kind: "load", Count: 1}))
	rows, err := (coordinatorCommand{PublisherWorkers: 2, LoadWorkers: 1, Routes: 2}).execute(ctx, client)
	if err == nil || len(rows) != 3 {
		t.Fatalf("conflict not rejected/partial results lost: %v rows=%d", err, len(rows))
	}
	if found, _ := client.Get(ctx, "publish.stop", nil); !found {
		t.Fatal("failure did not release publisher cleanup")
	}
}
