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
	if err := h.blackhole(t.Context(), time.Now(), nil); err == nil || !strings.Contains(err.Error(), "requires planned publishers") {
		t.Fatalf("UDP fallback accepted missing publishers: %v", err)
	}
	h = runtimeHarness{selected: "publisher-blackhole", plan: map[string][]string{"fault-sources": {"source"}, "fault-destinations": {"planned-replica"}}}
	if err := h.blackhole(t.Context(), time.Now(), nil); err == nil || !strings.Contains(err.Error(), "component planned-replica is missing") {
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

const publisherDNSFixture = "UNCONN 0 0 127.0.0.11:38881 0.0.0.0:* ino:100 sk:10 cgroup:unreachable:1 <->\n"

func publisherUDPFixture(inode, cookie, pid, fd int) string {
	return fmt.Sprintf("UNCONN 0 0 *:%d *:* users:((\"runtime.test\",pid=%d,fd=%d)) uid:0 ino:%d sk:%x v6only:0 <->\n",
		40000+fd, pid, fd, inode, cookie)
}

func TestParsePublisherUDPRequiresKernelAndProcessOwnership(t *testing.T) {
	socket := publisherUDPFixture(101, 17, 9, 21)
	parse := func(output string) []publisherUDPSocket {
		t.Helper()
		sockets, err := parsePublisherUDP(output)
		if err != nil {
			t.Fatal(err)
		}
		return sockets
	}
	got := parse(socket + publisherDNSFixture)
	want := []publisherUDPSocket{
		{Address: "127.0.0.11:38881", Inode: 100, Cookie: 16},
		{Address: "*:40021", Inode: 101, Cookie: 17, PID: 9, FD: 21},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("UDP identities=%+v, want %+v", got, want)
	}
	for _, host := range []string{"0.0.0.0", "[::]"} {
		parse(strings.Replace(socket, "*:40021", host+":40021", 1))
	}
	for _, test := range []struct{ name, output string }{
		{"stderr is not socket evidence", "Failed to open cgroup2 by ID\n" + socket},
		{"short row", "UNCONN 0 0 *:40021 *:*"},
		{"queue", strings.Replace(socket, "UNCONN 0 0", "UNCONN invalid 0", 1)},
		{"connected attempt", strings.Replace(socket, "UNCONN", "ESTAB", 1)},
		{"remote peer", strings.Replace(socket, "*:*", "192.0.2.1:443", 1)},
		{"unexpected local address", strings.Replace(socket, "*:40021", "192.0.2.1:40021", 1)},
		{"missing owner", strings.Replace(socket, `users:(("runtime.test",pid=9,fd=21)) `, "", 1)},
		{"different owner", strings.Replace(socket, "runtime.test", "unrelated", 1)},
		{"multiple owners", strings.Replace(socket, `fd=21))`, `fd=21),("other",pid=10,fd=22))`, 1)},
		{"invalid process", strings.Replace(socket, "pid=9", "pid=0", 1)},
		{"overflow process", strings.Replace(socket, "pid=9", "pid=18446744073709551616", 1)},
		{"missing inode", strings.Replace(socket, "ino:101 ", "", 1)},
		{"missing cookie", strings.Replace(socket, "sk:11 ", "", 1)},
		{"invalid inode", strings.Replace(socket, "ino:101", "ino:invalid", 1)},
		{"invalid cookie", strings.Replace(socket, "sk:11", "sk:invalid", 1)},
		{"zero inode", strings.Replace(socket, "ino:101", "ino:0", 1)},
		{"zero cookie", strings.Replace(socket, "sk:11", "sk:0", 1)},
		{"duplicate metadata", strings.Replace(socket, "ino:101", "ino:101 ino:102", 1)},
		{"duplicate row", socket + socket},
		{"duplicate inode", socket + publisherUDPFixture(101, 18, 9, 22)},
		{"duplicate cookie", socket + publisherUDPFixture(102, 17, 9, 22)},
		{"DNS address is not an owner exemption", strings.Replace(socket, "*:40021", "127.0.0.11:40021", 1)},
		{"unowned wildcard", strings.Replace(publisherDNSFixture, "127.0.0.11:38881", "*:38881", 1)},
		{"invalid port", strings.Replace(socket, "*:40021", "*:65536", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parsePublisherUDP(test.output); err == nil {
				t.Fatalf("accepted invalid socket evidence: %q", test.output)
			}
		})
	}
}

func TestPublisherUDPBoundsFollowPlannedPublicationOwnership(t *testing.T) {
	plan := map[string][]string{
		"publishers":                   {"selected", "selected-2"},
		"fault-sources":                {"selected", "selected-2"},
		"fault-destinations":           {"relay"},
		"publisher-indexes.selected":   {"0", "1", "8", "9"},
		"publisher-indexes.selected-2": {"2"},
		"publisher-indexes.unused":     {"3", "4"},
	}
	counts, err := publisherUDPSocketCounts(plan)
	if err != nil || !reflect.DeepEqual(counts, map[string]int{"selected": 8, "selected-2": 2}) {
		t.Fatalf("socket bounds=%v error=%v", counts, err)
	}
	for _, plan := range []map[string][]string{
		nil,
		{"publishers": {"selected"}},
		{"publishers": {"selected", "selected"}, "publisher-indexes.selected": {"0"}},
		{"publishers": {"selected"}, "publisher-indexes.selected": {"invalid"}},
		{"publishers": {"selected"}, "publisher-indexes.selected": {"-1"}},
		{"publishers": {"selected"}, "publisher-indexes.selected": {"0", "0"}},
		{"publishers": {"selected", "selected-2"}, "publisher-indexes.selected": {"0"}, "publisher-indexes.selected-2": {"0"}},
	} {
		if _, err := publisherUDPSocketCounts(plan); err == nil {
			t.Fatalf("accepted missing or ambiguous publication ownership: %v", plan)
		}
	}
	h := runtimeHarness{selected: "udp-fallback", plan: plan}
	if err := h.blackhole(t.Context(), time.Now(), nil); err == nil || !strings.Contains(err.Error(), "socket lifecycle proof") {
		t.Fatalf("UDP blackhole accepted missing lifecycle proof: %v", err)
	}
}

func TestPublisherUDPLifecycleRejectsAttemptsReplacementAndShutdownLeaks(t *testing.T) {
	parse := func(output string) []publisherUDPSocket {
		t.Helper()
		sockets, err := parsePublisherUDP(output)
		if err != nil {
			t.Fatal(err)
		}
		return sockets
	}
	baseline := parse(publisherDNSFixture)
	liveOutput := publisherDNSFixture + publisherUDPFixture(101, 17, 9, 21) + publisherUDPFixture(102, 18, 9, 22)
	live := parse(liveOutput)
	for _, phase := range []struct {
		name                string
		sockets, identities []publisherUDPSocket
		expected            int
	}{
		{"before-publication", baseline, nil, 0},
		{"fallback", live, nil, 2},
		{"before-restoration", live, live, 2},
		{"recovered", live, live, 2},
		{"closed", baseline, baseline, 0},
	} {
		if err := validatePublisherUDP(phase.sockets, baseline, phase.identities, phase.expected); err != nil {
			t.Fatalf("%s rejected the bounded lifecycle: %v", phase.name, err)
		}
	}
	for _, test := range []struct {
		name, output string
		expected     int
		identities   []publisherUDPSocket
	}{
		{"abandoned attempt at fallback", liveOutput + publisherUDPFixture(103, 19, 9, 23), 2, nil},
		{"missing run socket", publisherDNSFixture + publisherUDPFixture(101, 17, 9, 21), 2, nil},
		{"accumulated attempt during fallback", liveOutput + publisherUDPFixture(103, 19, 9, 23), 2, live},
		{"accumulated attempt after recovery", liveOutput + publisherUDPFixture(104, 20, 9, 24), 2, live},
		{"same count replaced inode", strings.Replace(liveOutput, "ino:101", "ino:103", 1), 2, live},
		{"same count replaced cookie", strings.Replace(liveOutput, "sk:11", "sk:13", 1), 2, live},
		{"same count replaced fd", strings.Replace(liveOutput, "fd=21", "fd=23", 1), 2, live},
		{"same count replaced port", strings.Replace(liveOutput, "*:40021", "*:40023", 1), 2, live},
		{"same count restarted process", strings.ReplaceAll(liveOutput, "pid=9", "pid=10"), 2, live},
		{"multiple processes", strings.Replace(liveOutput, "pid=9", "pid=10", 1), 2, nil},
		{"DNS identity changed", strings.Replace(liveOutput, "ino:100", "ino:104", 1), 2, live},
		{"extra DNS socket", liveOutput + strings.ReplaceAll(strings.ReplaceAll(publisherDNSFixture, "ino:100", "ino:104"), "sk:10", "sk:14"), 2, nil},
		{"live socket after joined shutdown", publisherDNSFixture + publisherUDPFixture(101, 17, 9, 21), 0, baseline},
		{"new attempt after joined shutdown", publisherDNSFixture + publisherUDPFixture(104, 20, 9, 24), 0, baseline},
		{"socket before publication", liveOutput, 0, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validatePublisherUDP(parse(test.output), baseline, test.identities, test.expected); err == nil {
				t.Fatal("accepted a missing, replaced, or leaked socket")
			}
		})
	}
}

func TestUDPFallbackCompletionRequiresRecoveryAndJoinedShutdownProofs(t *testing.T) {
	want := []string{
		"wait:udp.recovered", "check:recovered", "signal:udp.recovery-checked",
		"wait:udp.publishers-joined", "check:closed", "signal:udp.closed",
	}
	for failAt := -1; failAt < len(want); failAt++ {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			failure := errors.New("lifecycle evidence failed")
			var calls []string
			record := func(operation, name string) error {
				calls = append(calls, operation+":"+name)
				if len(calls)-1 == failAt {
					return failure
				}
				return nil
			}
			err := finishUDPFallback(
				func(name string) error { return record("wait", name) },
				func(name string) error { return record("check", name) },
				func(name string) error { return record("signal", name) },
			)
			expected := want
			if failAt >= 0 {
				expected = want[:failAt+1]
				if !errors.Is(err, failure) {
					t.Fatalf("lost lifecycle failure: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(calls, expected) {
				t.Fatalf("completion order=%v, want=%v", calls, expected)
			}
		})
	}
}
