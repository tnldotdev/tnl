package main

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestValidateRequiresCanonicalBenchmarkInputs(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	valid := cli{
		Topology: "standalone", ServerURL: "https://server.example", LoginToken: "login",
		PublicAddress: address, HostnameSuffix: "bench.example", Routes: 1, DriverCount: 1,
		Parallel: 1, PayloadBytes: 1, Timeout: 1, Repetition: 1,
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.HostnameSuffix = "Bench.Example"
	if err := invalid.Validate(); err == nil {
		t.Fatal("non-canonical hostname suffix was accepted")
	}
}

func TestBenchmarkHostnameSuffixUsesConfiguredTeamDomain(t *testing.T) {
	discovery := controlv1.ControlDiscovery{ManagedDeploymentDomain: "tnl.dev"}
	got, err := benchmarkHostnameSuffix(discovery, "chase-abc.tnl.dev")
	if err != nil || got != "chase-abc.tnl.dev" {
		t.Fatalf("suffix = %q, %v", got, err)
	}
	discovery.ManagedDeploymentDomain = "Invalid."
	if _, err := benchmarkHostnameSuffix(discovery, "chase-abc.tnl.dev"); err == nil {
		t.Fatal("invalid managed deployment domain was accepted")
	}
}

func TestCleanupDeletesDurableRoutesAfterPublisherStops(t *testing.T) {
	cleaner := &cleanerStub{routes: []controlv1.Route{{Id: "route_1", TeamId: "team_1"}}}
	done := make(chan error, 1)
	done <- nil
	processes := []*routeProcess{{teamID: "team_1", routeID: "route_1", cancel: func() {}, done: done}}
	if _, err := cleanupRoutes(t.Context(), cli{Parallel: 1}, cleaner, processes); err != nil {
		t.Fatal(err)
	}
	if len(cleaner.deleted) != 1 || cleaner.deleted[0] != "route_1" {
		t.Fatalf("deleted routes = %#v", cleaner.deleted)
	}
}

type cleanerStub struct {
	mu      sync.Mutex
	routes  []controlv1.Route
	deleted []string
}

func (c *cleanerStub) ListRoutes(context.Context, string) ([]controlv1.Route, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]controlv1.Route(nil), c.routes...), nil
}

func (c *cleanerStub) DeleteRoute(_ context.Context, route controlv1.Route) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deleted = append(c.deleted, route.Id)
	c.routes = nil
	return nil
}
