package main

import (
	"context"
	"errors"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestLoadValidationProtectsSourceLimiter(t *testing.T) {
	valid := loadCommand{
		workerCommand: workerCommand{
			CellID: "cell", Suite: "smoke", Axis: "smoke", Repetition: 1, CoordinatorURL: "http://coordinator.internal:8080",
			CoordinatorToken: "secret", WorkerCount: 1,
		},
		Routes: 1, TotalFreshRate: 30, TotalHeldStreams: 1,
		FreshRate: 30, HeldStreams: 1, Warmup: 1, Duration: 1,
		PayloadBytes: 1, Timeout: 1,
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	valid.FreshRate = 40
	if err := valid.Validate(); err == nil {
		t.Fatal("source-limiter rate was accepted")
	}
	valid.FreshRate = 30
	valid.ResolverAddress = "missing-port"
	if err := valid.Validate(); err == nil {
		t.Fatal("invalid resolver address was accepted")
	}
}

func TestPublisherRouteShardingUsesStableBands(t *testing.T) {
	var all []int
	for worker := range 5 {
		indexes := benchmarkRouteIndexes(43, 10, 5, worker)
		for _, index := range indexes {
			if index/10 != worker {
				t.Fatalf("route %d assigned to worker %d", index, worker)
			}
		}
		all = append(all, indexes...)
	}
	slices.Sort(all)
	want := make([]int, 43)
	for index := range want {
		want[index] = index
	}
	if !slices.Equal(all, want) {
		t.Fatalf("routes = %v", all)
	}
	if got := benchmarkRouteIndexes(2, 10, 4, 3); len(got) != 0 {
		t.Fatalf("invalid publisher layout routes = %v", got)
	}
}

func TestPublisherValidationAcceptsOneStableBand(t *testing.T) {
	loginToken, err := credentials.NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	command := publisherCommand{
		workerCommand: workerCommand{
			CellID: "cell", Suite: "smoke", Axis: "smoke", Repetition: 1, CoordinatorURL: "http://coordinator.internal:8080",
			CoordinatorToken: "secret", WorkerCount: 1,
		},
		ServerURL: "https://control.example.com", LoginToken: string(loginToken), HostnameSuffix: "routes.example.com",
		Routes: 2, AssignedRoutes: 2, RoutesPerPublisher: 10, RoutesPerChurn: 10, StateRoot: "/state",
		FreshRate: 2, Parallel: 1, PayloadBytes: 1, Timeout: 1,
	}
	if err := command.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestPublisherDiscoveryRetriesUnavailableControl(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		attempts := 0
		want := controlv1.ControlDiscovery{AuthorityEndpoint: "https://control.example.test"}
		got, err := retryBenchmarkDiscovery(t.Context(), time.Minute, func(context.Context) (controlv1.ControlDiscovery, error) {
			attempts++
			if attempts == 1 {
				return controlv1.ControlDiscovery{}, controlclient.ErrUnavailable
			}
			return want, nil
		})
		if err != nil || got.AuthorityEndpoint != want.AuthorityEndpoint || attempts != 2 {
			t.Fatalf("discovery = %#v, attempts = %d, error = %v", got, attempts, err)
		}

		wantErr := errors.New("invalid discovery response")
		_, err = retryBenchmarkDiscovery(t.Context(), time.Minute, func(context.Context) (controlv1.ControlDiscovery, error) {
			return controlv1.ControlDiscovery{}, wantErr
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("discovery error = %v, want %v", err, wantErr)
		}
	})
}

func TestStopRoutesWaitsForPublisherAndPreservesDurableRoute(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		canceled := make(chan struct{})
		done := make(chan error, 1)
		processes := []*routeProcess{{index: 7, routeID: "route_1", cancel: func() { close(canceled) }, done: done}}
		finished := make(chan error, 1)
		go func() { _, err := stopRoutes(t.Context(), processes); finished <- err }()
		synctest.Wait()
		select {
		case <-canceled:
		default:
			t.Error("publisher was not canceled")
		}
		done <- nil
		if err := <-finished; err != nil {
			t.Fatal(err)
		}
		if processes[0].routeID != "route_1" {
			t.Fatal("durable route identity changed while stopping its route session")
		}
	})
}
