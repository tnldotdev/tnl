package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func TestDNSReadinessRetriesPropagationAndRecordsPhase(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	var mu sync.Mutex
	calls := make(map[string]int)
	phase, err := waitForBenchmarkDNS(ctx, []string{"first.test", "second.test"}, func(_ context.Context, hostname string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls[hostname]++
		if calls[hostname] == 1 {
			return nil, errors.New("not propagated")
		}
		return []string{"192.0.2.1"}, nil
	}, time.Millisecond)
	if err != nil || phase.Name != "dns_readiness" || phase.Attempts != 2 || phase.Successes != 2 || phase.Errors != 0 || phase.DNS.Count != 2 {
		t.Fatalf("DNS readiness = %+v, %v", phase, err)
	}
	if phase.DurationMilliseconds <= 0 || calls["first.test"] != 2 || calls["second.test"] != 2 {
		t.Fatalf("propagation not recorded: phase=%+v calls=%v", phase, calls)
	}
}

func TestDNSReadinessCancellationRecordsFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	phase, err := waitForBenchmarkDNS(ctx, []string{"missing.test"}, func(context.Context, string) ([]string, error) {
		cancel()
		return nil, nil
	}, time.Hour)
	if !errors.Is(err, context.Canceled) || phase.Successes != 0 || phase.Errors != 1 || phase.Attempts != 1 {
		t.Fatalf("canceled DNS readiness = %+v, %v", phase, err)
	}
}

func TestDNSReadinessBoundsParallelLookups(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	hostnames := make([]string, 25)
	for index := range hostnames {
		hostnames[index] = fmt.Sprintf("route-%d.test", index)
	}
	var mu sync.Mutex
	active, peak := 0, 0
	entered := make(chan struct{}, len(hostnames))
	release := make(chan struct{})
	go func() {
		defer close(release)
		for range 8 {
			select {
			case <-entered:
			case <-ctx.Done():
				return
			}
		}
	}()
	phase, err := waitForBenchmarkDNS(ctx, hostnames, func(context.Context, string) ([]string, error) {
		mu.Lock()
		active++
		peak = max(peak, active)
		mu.Unlock()
		entered <- struct{}{}
		<-release
		defer func() { mu.Lock(); active--; mu.Unlock() }()
		return []string{"192.0.2.1"}, nil
	}, time.Millisecond)
	if err != nil || phase.Successes != len(hostnames) || peak != 8 || active != 0 {
		t.Fatalf("bounded lookups = %+v peak=%d active=%d err=%v", phase, peak, active, err)
	}
}

func TestLoadPostsDNSReadinessFailureWithoutMeasuringTraffic(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	state := newCoordinatorState("cell-1", 1, 1, 1)
	coordinator := httptest.NewServer(coordinatorHandler("secret", state))
	defer coordinator.Close()
	client, err := newCoordinatorClient(coordinator.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.publisherReady(ctx, 0, []benchmarkRouteRegistration{{Index: 0, Hostname: "missing.example.test"}}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &mdns.Server{Listener: listener, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, request *mdns.Msg) {
		response := new(mdns.Msg)
		response.SetRcode(request, mdns.RcodeNameError)
		_ = w.WriteMsg(response)
		cancel()
	})}
	serving := make(chan error, 1)
	go func() { serving <- server.ActivateAndServe() }()
	defer func() {
		_ = server.Shutdown()
		if err := <-serving; err != nil {
			t.Error(err)
		}
	}()
	command := loadCommand{
		workerCommand: workerCommand{CellID: "cell-1", Suite: "scout", Repetition: 1, WorkerCount: 1, CoordinatorURL: coordinator.URL, CoordinatorToken: "secret"},
		Routes:        1, ResolverAddress: listener.Addr().String(), Timeout: time.Minute,
	}
	if err := command.run(ctx); err == nil {
		t.Fatal("DNS setup failure unexpectedly passed")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	result, found := state.results["load:0"]
	if !found || result.Status != "failed" || resultFailureStage(result) != "setup" || len(result.Phases) != 2 ||
		result.Phases[0].Name != "dns_readiness" || result.Phases[0].Errors != 1 || result.Phases[1].Name != "worker" {
		t.Fatalf("setup result lost DNS evidence or ran measurement: %+v", result)
	}
}
