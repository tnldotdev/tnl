package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
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

func TestFaultNetworkSelectionAndInputs(t *testing.T) {
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
	forward, err := impairmentEndpoints("forwarding", addresses, []string{"ingress-a"}, []string{"publishers"}, nil)
	if err != nil || len(forward) != 3 || len(forward[0].Filters) != 2 || forward[0].Filters[0][12] != "8443" {
		t.Fatalf("forwarding impairment = %+v, %v", forward, err)
	}
	publisher, err := impairmentEndpoints("publisher", addresses, []string{"ingress-a"}, []string{"publishers"}, nil)
	if err != nil || len(publisher) != 3 || len(publisher[0].Filters) != 4 || publisher[0].Filters[0][12] != "443" {
		t.Fatalf("publisher impairment = %+v, %v", publisher, err)
	}
	if _, err := impairmentEndpoints("invalid", addresses, nil, nil, nil); err == nil {
		t.Fatal("invalid network path accepted")
	}
	for _, delay := range []string{"0ms", "50ms", "100ms"} {
		options, err := controlDelayOptions(delay)
		if err != nil || (delay == "0ms") != (len(options) == 0) {
			t.Fatal("control delay cohort changed", delay, options, err)
		}
	}
	if _, err := controlDelayOptions("25ms"); err == nil {
		t.Fatal("unmatched control delay cohort was accepted")
	}
	addresses["control-a"], addresses["control-b"] = "192.0.2.6", "192.0.2.7"
	separated := controlImpairmentEndpoints(forward, addresses, []string{"ingress-a", "publishers"}, []string{"control-a", "control-b"})
	if len(separated) != 4 || len(separated[0].Filters) != 2 || len(separated[0].ControlFilters) != 6 ||
		len(separated[3].ControlFilters) != 6 || !strings.Contains(strings.Join(separated[0].ControlFilters[0], " "), "dst 192.0.2.6 match ip protocol 6") ||
		!strings.Contains(strings.Join(separated[3].ControlFilters[5], " "), "dst 192.0.2.7 match ip protocol 6") {
		t.Fatal("control-only filters changed data-path impairment or missed a publisher", separated)
	}
	addresses["visitor-1"] = "192.0.2.5"
	connector, err := impairmentEndpoints("connector", addresses, []string{"ingress-a"}, nil, []string{"visitor-1"})
	if err != nil || len(connector) != 2 || len(connector[0].Filters) != 2 || !strings.Contains(strings.Join(connector[0].Filters[1], " "), "dst 192.0.2.1 match ip protocol 17") || !strings.Contains(strings.Join(connector[1].Filters[0], " "), "dst 192.0.2.5 match ip protocol 6") {
		t.Fatalf("connector impairment must cover TCP/UDP in both directions: %+v, %v", connector, err)
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
}
