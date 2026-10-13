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
	forward, err := impairmentEndpoints("forwarding", addresses, []string{"ingress-a"}, []string{"publishers"})
	if err != nil || len(forward) != 3 || len(forward[0].Filters) != 2 || forward[0].Filters[0][12] != "8443" {
		t.Fatalf("forwarding impairment = %+v, %v", forward, err)
	}
	publisher, err := impairmentEndpoints("publisher", addresses, []string{"ingress-a"}, []string{"publishers"})
	if err != nil || len(publisher) != 3 || len(publisher[0].Filters) != 4 || publisher[0].Filters[0][12] != "443" {
		t.Fatalf("publisher impairment = %+v, %v", publisher, err)
	}
	if _, err := impairmentEndpoints("invalid", addresses, nil, nil); err == nil {
		t.Fatal("invalid network path accepted")
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
