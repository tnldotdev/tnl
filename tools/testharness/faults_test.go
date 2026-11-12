package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestFaultCleanupRetainsCauseAndReversesAppliedCommands(t *testing.T) {
	setup := errors.New("fault setup failed")
	cleanup := errors.New("restore failed")
	var commands []string
	err := withFaultCleanup(t.Context(), func(_ context.Context, parts ...string) (string, error) {
		commands = append(commands, strings.Join(parts, " "))
		if parts[0] == "undo-a" {
			return "", cleanup
		}
		return "", nil
	}, func(undo func(...string)) error {
		undo("undo-a")
		undo("undo-b")
		return setup
	})
	if !errors.Is(err, setup) || !errors.Is(err, cleanup) || !reflect.DeepEqual(commands, []string{"undo-b", "undo-a"}) {
		t.Fatalf("fault cleanup = %v, calls = %v", err, commands)
	}
}

func TestFaultNetworkInputsAndPlannedEndpoints(t *testing.T) {
	if options, err := netemOptions("latency", "20ms", "", "7"); err != nil || !reflect.DeepEqual(options, []string{"delay", "10ms", "seed", "7"}) {
		t.Fatalf("latency options = %v, %v", options, err)
	}
	if options, err := netemOptions("packet-loss", "", "0.1", "0"); err != nil || !reflect.DeepEqual(options, []string{"loss", "random", "0.1%"}) {
		t.Fatalf("loss options = %v, %v", options, err)
	}
	for _, invalid := range []struct{ scenario, rtt, loss, seed string }{
		{"latency", "other", "", "0"}, {"packet-loss", "", "10", "0"},
		{"latency", "20ms", "", "not-a-number"}, {"latency", "20ms", "", "4294967296"},
	} {
		if _, err := netemOptions(invalid.scenario, invalid.rtt, invalid.loss, invalid.seed); err == nil {
			t.Fatalf("invalid network fault inputs accepted: %+v", invalid)
		}
	}
	addresses := map[string]string{"ingress-a": "192.0.2.1", "publishers": "192.0.2.2", "relay-a": "192.0.2.3", "relay-b": "192.0.2.4"}
	forward, err := impairmentEndpoints("forwarding", addresses, []string{"ingress-a"}, []string{"relay-a", "relay-b"})
	if err != nil || len(forward) != 3 || len(forward[0].Filters) != 2 || forward[0].Filters[0][12] != "8443" {
		t.Fatalf("forwarding impairment = %+v, %v", forward, err)
	}
	publisher, err := impairmentEndpoints("publisher", addresses, []string{"publishers"}, []string{"relay-a", "relay-b"})
	if err != nil || len(publisher) != 3 || len(publisher[0].Filters) != 4 || publisher[0].Filters[0][12] != "443" {
		t.Fatalf("publisher impairment = %+v, %v", publisher, err)
	}
	if _, err := impairmentEndpoints("invalid", addresses, nil, nil); err == nil {
		t.Fatal("invalid network path accepted")
	}
	addresses["visitor-1"] = "192.0.2.5"
	connector, err := impairmentEndpoints("connector", addresses, []string{"visitor-1"}, []string{"relay-a", "relay-b"})
	if err != nil || len(connector) != 3 || len(connector[0].Filters) != 4 || !strings.Contains(strings.Join(connector[0].Filters[1], " "), "dst 192.0.2.3 match ip protocol 17") || !strings.Contains(strings.Join(connector[0].Filters[3], " "), "dst 192.0.2.4 match ip protocol 17") || !strings.Contains(strings.Join(connector[1].Filters[0], " "), "dst 192.0.2.5 match ip protocol 6") {
		t.Fatalf("connector impairment must cover TCP/UDP in both directions: %+v, %v", connector, err)
	}
	for _, endpoint := range connector {
		if endpoint.Service == "ingress-a" {
			t.Fatal("native impairment still targets ingress")
		}
	}
}

func TestImpairmentUsesOnlyPlannedSourcesAndDestinations(t *testing.T) {
	addresses := map[string]string{
		"selected-source": "192.0.2.1", "selected-source-2": "192.0.2.2",
		"selected-destination": "192.0.2.3", "selected-replica": "192.0.2.4",
		"ingress-a": "192.0.2.5", "publishers-4": "192.0.2.6", "relay-a": "192.0.2.7",
	}
	sources, destinations := []string{"selected-source", "selected-source-2"}, []string{"selected-destination", "selected-replica"}
	for _, path := range []string{"forwarding", "publisher", "connector"} {
		endpoints, err := impairmentEndpoints(path, addresses, sources, destinations)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, endpoint := range endpoints {
			names = append(names, endpoint.Service)
		}
		if !slices.Equal(names, slices.Concat(sources, destinations)) {
			t.Fatalf("%s selected unplanned endpoints: %v", path, names)
		}
		port, protocols := "8443", []string{"6"}
		if path != "forwarding" {
			port, protocols = "443", []string{"6", "17"}
		}
		for index, source := range sources {
			var want []string
			for _, destination := range destinations {
				for _, protocol := range protocols {
					want = append(want, fmt.Sprintf("match ip dst %s match ip protocol %s 0xff match ip dport %s 0xffff", addresses[destination], protocol, port))
				}
			}
			var got []string
			for _, filter := range endpoints[index].Filters {
				got = append(got, strings.Join(filter, " "))
			}
			if !slices.Equal(got, want) {
				t.Fatalf("%s forward filters for %s=%v, want %v", path, source, got, want)
			}
		}
		for index, destination := range destinations {
			var want []string
			for _, source := range sources {
				for _, protocol := range protocols {
					want = append(want, fmt.Sprintf("match ip dst %s match ip protocol %s 0xff match ip sport %s 0xffff", addresses[source], protocol, port))
				}
			}
			var got []string
			for _, filter := range endpoints[len(sources)+index].Filters {
				got = append(got, strings.Join(filter, " "))
			}
			if !slices.Equal(got, want) {
				t.Fatalf("%s reverse filters for %s=%v, want %v", path, destination, got, want)
			}
		}
	}
}

func TestImpairmentRejectsEmptyOrUnaddressedPlans(t *testing.T) {
	for _, path := range []string{"forwarding", "publisher", "connector"} {
		for _, test := range []struct {
			addresses             map[string]string
			sources, destinations []string
		}{
			{nil, nil, nil},
			{nil, []string{"source"}, nil},
			{nil, nil, []string{"destination"}},
			{map[string]string{"source": "192.0.2.1"}, []string{"source"}, []string{"destination"}},
			{map[string]string{"destination": "192.0.2.2"}, []string{"source"}, []string{"destination"}},
		} {
			if _, err := impairmentEndpoints(path, test.addresses, test.sources, test.destinations); err == nil {
				t.Fatalf("%s accepted missing network endpoints: %+v", path, test)
			}
		}
	}
}

func TestRelayKillRequiresOnePresentPlannedTarget(t *testing.T) {
	for _, targets := range [][]string{nil, {}, {"planned-relay", "other-relay"}} {
		h := runtimeHarness{selected: "relay-kill", plan: map[string][]string{"fault-targets": targets}}
		if err := h.applyFault(t.Context()); err == nil || !strings.Contains(err.Error(), "exactly one planned fault target") {
			t.Fatalf("invalid kill plan %v: %v", targets, err)
		}
	}
	h := runtimeHarness{selected: "relay-kill", plan: map[string][]string{"fault-targets": {"planned-replica"}}}
	if err := h.applyFault(t.Context()); err == nil || !strings.Contains(err.Error(), "fault target planned-replica is missing") {
		t.Fatalf("kill did not use its planned target: %v", err)
	}
}

func TestNetworkFaultsRejectEmptyPlansBeforeApplying(t *testing.T) {
	t.Setenv("NETWORK_PATH", "publisher")
	t.Setenv("RTT", "20ms")
	t.Setenv("SEED", "0")
	for _, scenario := range []string{"forwarding-blackhole", "publisher-blackhole", "udp-fallback", "latency"} {
		for _, plan := range []map[string][]string{
			nil, {"fault-sources": {"source"}}, {"fault-destinations": {"destination"}},
		} {
			h := runtimeHarness{selected: scenario, plan: plan}
			if err := h.applyFault(t.Context()); err == nil || !strings.Contains(err.Error(), "sources and destinations") {
				t.Fatalf("%s accepted empty network plan %v: %v", scenario, plan, err)
			}
		}
	}
	h := runtimeHarness{selected: "udp-fallback", plan: map[string][]string{"fault-sources": {"source"}, "fault-destinations": {"destination"}}}
	if err := h.blackhole(t.Context(), time.Now()); err == nil || !strings.Contains(err.Error(), "requires planned publishers") {
		t.Fatalf("UDP fallback accepted missing publishers: %v", err)
	}
	h = runtimeHarness{selected: "publisher-blackhole", plan: map[string][]string{"fault-sources": {"source"}, "fault-destinations": {"planned-replica"}}}
	if err := h.blackhole(t.Context(), time.Now()); err == nil || !strings.Contains(err.Error(), "component planned-replica is missing") {
		t.Fatalf("blackhole did not use its planned destination: %v", err)
	}
}

func TestBlackholeEvidenceRequiresDroppedPackets(t *testing.T) {
	for _, counters := range []string{"invalid 0 0 DROP tnl-runtime-fault", "0 0 0 DROP tnl-runtime-fault"} {
		if err := validateBlackholeCounters(counters, 1); err == nil {
			t.Fatalf("invalid packet count accepted: %q", counters)
		}
	}
	if err := validateBlackholeCounters("12 0 0 DROP tnl-runtime-fault", 1); err != nil {
		t.Fatal(err)
	}
	if err := validateBlackholeCounters("", 0); err == nil {
		t.Fatal("accepted empty blackhole evidence")
	}
	if err := validateBlackholeCounters("12 0 0 DROP tnl-runtime-fault", 2); err == nil {
		t.Fatal("accepted missing blackhole rules")
	}
}
