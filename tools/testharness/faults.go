package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type impairmentEndpoint struct {
	Service string     `json:"service"`
	Filters [][]string `json:"filters"`
}

func (h *runtimeHarness) applyFault(ctx context.Context) error {
	started := time.Now().UTC()
	switch h.selected {
	case "relay-kill":
		if len(h.plan["fault-targets"]) != 1 {
			return errors.New("relay kill requires exactly one planned fault target")
		}
		target := h.plan["fault-targets"][0]
		container := h.containers[target]
		if container == nil {
			return fmt.Errorf("runtime fault target %s is missing", target)
		}
		h.intentional.Store(true)
		if _, err := h.compose(ctx, "kill", "--signal", "SIGKILL", target); err != nil {
			return err
		}
		state, err := container.State(ctx)
		if err != nil || state.Running || state.ExitCode != 137 {
			return fmt.Errorf("relay kill did not produce the expected process exit: %v", err)
		}
		if _, err := h.event(ctx, "fault.applied", map[string]any{"Started": started, "Exited": time.Now().UTC()}); err != nil {
			return err
		}
		if err := sleepRuntime(ctx, 31*time.Second); err != nil {
			return err
		}
		if _, err := h.compose(ctx, "start", target); err != nil {
			return err
		}
		h.intentional.Store(false)
	case "forwarding-blackhole", "publisher-blackhole":
		if err := h.blackhole(ctx, started, nil); err != nil {
			return err
		}
	case "udp-fallback":
		return h.udpFallback(ctx, started)
	case "latency", "packet-loss":
		if err := h.impair(ctx, started); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown runtime fault %q", h.selected)
	}
	_, err := h.event(ctx, "fault.restored", time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (h *runtimeHarness) withFaultCleanup(ctx context.Context, run func(func(...string)) error) error {
	return withFaultCleanup(ctx, h.compose, run)
}

func withFaultCleanup(ctx context.Context, command func(context.Context, ...string) (string, error), run func(func(...string)) error) error {
	undo := [][]string{}
	err := run(func(args ...string) { undo = append(undo, args) })
	cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for index := len(undo) - 1; index >= 0; index-- {
		_, cleanupErr := command(cleanup, undo[index]...)
		err = errors.Join(err, cleanupErr)
	}
	return err
}

func (h *runtimeHarness) blackhole(ctx context.Context, started time.Time, checkUDP func(string) error) error {
	sources, destinations := h.plan["fault-sources"], h.plan["fault-destinations"]
	if len(sources) == 0 || len(destinations) == 0 {
		return errors.New("blackhole requires planned fault sources and destinations")
	}
	port, protocols := "443", []string{"tcp"}
	switch h.selected {
	case "forwarding-blackhole":
		port = "8443"
	case "publisher-blackhole":
		protocols = []string{"tcp", "udp"}
	case "udp-fallback":
		protocols = []string{"udp"}
		if len(h.plan["publishers"]) == 0 {
			return errors.New("UDP fallback requires planned publishers")
		}
		if checkUDP == nil {
			return errors.New("UDP fallback requires a socket lifecycle proof")
		}
	default:
		return fmt.Errorf("unknown runtime blackhole %q", h.selected)
	}
	return h.withFaultCleanup(ctx, func(undo func(...string)) error {
		for _, source := range sources {
			for _, destination := range destinations {
				address, err := h.containerIP(ctx, destination)
				if err != nil {
					return err
				}
				for _, protocol := range protocols {
					rule := []string{"OUTPUT", "-d", address, "-p", protocol, "--dport", port,
						"-m", "comment", "--comment", "tnl-runtime-fault", "-j", "DROP"}
					if _, err := h.compose(ctx, append([]string{"exec", "-T", source, "iptables", "-I"}, rule...)...); err != nil {
						return err
					}
					undo(append([]string{"exec", "-T", source, "iptables", "-D"}, rule...)...)
				}
			}
		}
		if _, err := h.event(ctx, "fault.applied", map[string]any{"Started": started, "Exited": time.Now().UTC()}); err != nil {
			return err
		}
		if h.selected == "udp-fallback" {
			if err := h.waitEvent(ctx, "publishers.ready"); err != nil {
				return err
			}
			if err := checkUDP("fallback"); err != nil {
				return err
			}
			if _, err := h.event(ctx, "udp.fallback-checked", true); err != nil {
				return err
			}
		}
		if err := h.waitEvent(ctx, "fault.release"); err != nil {
			return err
		}
		if checkUDP != nil {
			if err := checkUDP("before-restoration"); err != nil {
				return err
			}
		}
		for _, source := range sources {
			counters, err := h.compose(ctx, "exec", "-T", source, "iptables", "-L", "OUTPUT", "-n", "-v", "-x")
			if err != nil {
				return err
			}
			if err := h.writeResult(h.selected+"-"+source+"-counters.txt", counters); err != nil {
				return err
			}
			if err := validateBlackholeCounters(counters, len(destinations)*len(protocols)); err != nil {
				return err
			}
		}
		return nil
	})
}

type publisherUDPSocket struct {
	Address string
	Inode   uint64
	Cookie  uint64
	PID     uint64
	FD      uint64
}

var publisherUDPOwner = regexp.MustCompile(`^users:\(\("runtime\.test",pid=([1-9][0-9]*),fd=([0-9]+)\)\)$`)

// retain every namespace socket, including docker dns. wildcard addresses alone
// never establish ownership; the publisher process and kernel identities must exist.
func parsePublisherUDP(output string) ([]publisherUDPSocket, error) {
	var sockets []publisherUDPSocket
	inodes, cookies := map[uint64]bool{}, map[uint64]bool{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 7 || fields[0] != "UNCONN" {
			return nil, fmt.Errorf("invalid UDP socket evidence: %q", line)
		}
		for _, queue := range fields[1:3] {
			if _, err := strconv.ParseUint(queue, 10, 64); err != nil {
				return nil, fmt.Errorf("invalid UDP queue evidence: %q", line)
			}
		}
		host, port, err := net.SplitHostPort(fields[3])
		number, portErr := strconv.ParseUint(port, 10, 16)
		if err != nil || portErr != nil || number == 0 ||
			(host != "*" && host != "::" && host != "0.0.0.0" && host != "127.0.0.11") ||
			(fields[4] != "*:*" && fields[4] != "0.0.0.0:*" && fields[4] != "[::]:*") {
			return nil, fmt.Errorf("unexpected UDP endpoint: %q", line)
		}
		socket := publisherUDPSocket{Address: fields[3]}
		seen := map[string]bool{}
		for _, field := range fields[5:] {
			name, value, _ := strings.Cut(field, ":")
			if name != "ino" && name != "sk" && name != "users" {
				continue
			}
			if seen[name] {
				return nil, fmt.Errorf("duplicate UDP %s evidence: %q", name, line)
			}
			seen[name] = true
			switch name {
			case "ino", "sk":
				base := 10
				if name == "sk" {
					base = 16
				}
				identity, err := strconv.ParseUint(value, base, 64)
				if err != nil || identity == 0 {
					return nil, fmt.Errorf("invalid UDP %s identity: %q", name, line)
				}
				if name == "ino" {
					socket.Inode = identity
				} else {
					socket.Cookie = identity
				}
			case "users":
				owner := publisherUDPOwner.FindStringSubmatch(field)
				if owner == nil {
					return nil, fmt.Errorf("unexpected UDP socket owner: %q", line)
				}
				var pidErr, fdErr error
				socket.PID, pidErr = strconv.ParseUint(owner[1], 10, 64)
				socket.FD, fdErr = strconv.ParseUint(owner[2], 10, 64)
				if pidErr != nil || fdErr != nil {
					return nil, fmt.Errorf("invalid UDP process identity: %q", line)
				}
			}
		}
		if socket.Inode == 0 || socket.Cookie == 0 || inodes[socket.Inode] || cookies[socket.Cookie] {
			return nil, fmt.Errorf("missing or duplicate UDP socket identity: %q", line)
		}
		if (host == "127.0.0.11") != (socket.PID == 0) {
			return nil, fmt.Errorf("UDP socket lacks the expected publisher or docker DNS owner: %q", line)
		}
		inodes[socket.Inode], cookies[socket.Cookie] = true, true
		sockets = append(sockets, socket)
	}
	slices.SortFunc(sockets, func(a, b publisherUDPSocket) int { return cmp.Compare(a.Inode, b.Inode) })
	return sockets, nil
}

func publisherUDPSocketCounts(plan map[string][]string) (map[string]int, error) {
	counts, indexes := map[string]int{}, map[int]bool{}
	if len(plan["publishers"]) == 0 {
		return nil, errors.New("UDP fallback requires planned publishers")
	}
	for _, publisher := range plan["publishers"] {
		if publisher == "" || counts[publisher] != 0 || len(plan["publisher-indexes."+publisher]) == 0 {
			return nil, fmt.Errorf("missing or duplicate UDP publication ownership for %q", publisher)
		}
		for _, raw := range plan["publisher-indexes."+publisher] {
			index, err := strconv.Atoi(raw)
			if err != nil || index < 0 || indexes[index] {
				return nil, fmt.Errorf("invalid or duplicate UDP publication index %q", raw)
			}
			indexes[index] = true
			// publish owns one run-wide quic socket and one direct-path peer
			// socket until it returns; per-attempt sockets get no allowance.
			counts[publisher] += 2
		}
	}
	return counts, nil
}

func validatePublisherUDP(sockets, baseline, identities []publisherUDPSocket, expected int) error {
	var dns []publisherUDPSocket
	owned, pid := 0, uint64(0)
	for _, socket := range sockets {
		if socket.PID == 0 {
			dns = append(dns, socket)
			continue
		}
		if pid != 0 && socket.PID != pid {
			return errors.New("UDP socket publisher process changed within the snapshot")
		}
		pid = socket.PID
		owned++
	}
	if owned != expected {
		return fmt.Errorf("publisher retained %d UDP sockets, want exactly %d run-owned sockets", owned, expected)
	}
	if !slices.Equal(dns, baseline) {
		return errors.New("non-publication UDP sockets changed from the pre-publication baseline")
	}
	if identities != nil && !slices.Equal(sockets, identities) {
		return errors.New("UDP socket identities changed")
	}
	return nil
}

func (h *runtimeHarness) publisherUDPSnapshot(ctx context.Context, phase string) (map[string][]publisherUDPSocket, error) {
	snapshot := map[string][]publisherUDPSocket{}
	for _, publisher := range h.plan["publishers"] {
		// one-line extended output carries inode/cookie and process fd ownership.
		// ss may warn about unavailable cgroups on stderr; retain that separately
		// so warnings cannot become socket rows or hide an unsuccessful command.
		name := publisher + "-udp-sockets-" + phase
		output, err := h.compose(ctx, "exec", "-T", publisher, "sh", "-ec",
			`ss -H -uanpeO 2>"$1"`, "udp-snapshot", "/results/"+name+"-stderr.txt")
		if err != nil {
			return nil, err
		}
		if err := h.writeResult(name+".txt", output); err != nil {
			return nil, err
		}
		sockets, err := parsePublisherUDP(output)
		if err != nil {
			return nil, fmt.Errorf("%s UDP sockets at %s: %w", publisher, phase, err)
		}
		snapshot[publisher] = sockets
	}
	return snapshot, nil
}

func (h *runtimeHarness) udpFallback(ctx context.Context, started time.Time) error {
	if len(h.plan["fault-sources"]) == 0 || len(h.plan["fault-destinations"]) == 0 {
		return errors.New("blackhole requires planned fault sources and destinations")
	}
	counts, err := publisherUDPSocketCounts(h.plan)
	if err != nil {
		return err
	}
	baseline, err := h.publisherUDPSnapshot(ctx, "before-publication")
	if err != nil {
		return err
	}
	for publisher, sockets := range baseline {
		if err := validatePublisherUDP(sockets, sockets, nil, 0); err != nil {
			return fmt.Errorf("%s before publication: %w", publisher, err)
		}
	}
	var live map[string][]publisherUDPSocket
	check := func(phase string) error {
		snapshot, err := h.publisherUDPSnapshot(ctx, phase)
		if err != nil {
			return err
		}
		for _, publisher := range h.plan["publishers"] {
			expected, identities := counts[publisher], live[publisher]
			if phase == "closed" {
				expected, identities = 0, baseline[publisher]
			}
			if err := validatePublisherUDP(snapshot[publisher], baseline[publisher], identities, expected); err != nil {
				return fmt.Errorf("%s at %s: %w", publisher, phase, err)
			}
			fmt.Fprintf(os.Stderr, "publisher_udp_sockets phase=%s publisher=%s owned=%d expected=%d\n",
				phase, publisher, expected, expected)
		}
		if phase == "fallback" {
			live = snapshot
		}
		return nil
	}
	if err := h.blackhole(ctx, started, check); err != nil {
		return err
	}
	if _, err := h.event(ctx, "fault.restored", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return finishUDPFallback(
		func(name string) error { return h.waitEvent(ctx, name) },
		check,
		func(name string) error { _, err := h.event(ctx, name, true); return err },
	)
}

// the coordinator cannot start partial shutdown before the recovery proof, or
// finish before the zero-socket proof after every publication stop has joined.
func finishUDPFallback(wait func(string) error, check func(string) error, signal func(string) error) error {
	for _, phase := range []struct{ ready, snapshot, checked string }{
		{"udp.recovered", "recovered", "udp.recovery-checked"},
		{"udp.publishers-joined", "closed", "udp.closed"},
	} {
		if err := wait(phase.ready); err != nil {
			return err
		}
		if err := check(phase.snapshot); err != nil {
			return err
		}
		if err := signal(phase.checked); err != nil {
			return err
		}
	}
	return nil
}

func validateBlackholeCounters(counters string, expected int) error {
	if expected < 1 {
		return errors.New("blackhole evidence requires at least one rule")
	}
	matched := 0
	for _, line := range strings.Split(counters, "\n") {
		if !strings.Contains(line, "tnl-runtime-fault") {
			continue
		}
		matched++
		fields := strings.Fields(line)
		if len(fields) == 0 {
			return errors.New("blackhole rule dropped no packets")
		}
		packets, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || packets == 0 {
			return errors.New("blackhole rule dropped no packets")
		}
	}
	if matched != expected {
		return errors.New("blackhole rule count changed during measurement")
	}
	return nil
}

func (h *runtimeHarness) impair(ctx context.Context, started time.Time) error {
	path := os.Getenv("NETWORK_PATH")
	options, err := netemOptions(h.selected, os.Getenv("RTT"), os.Getenv("LOSS"), os.Getenv("SEED"))
	if err != nil {
		return err
	}
	addresses := make(map[string]string)
	for _, service := range h.plan["fault-targets"] {
		addresses[service], err = h.containerIP(ctx, service)
		if err != nil {
			return err
		}
	}
	sources, destinations := h.plan["fault-sources"], h.plan["fault-destinations"]
	endpoints, err := impairmentEndpoints(path, addresses, sources, destinations)
	if err != nil {
		return err
	}
	return h.withFaultCleanup(ctx, func(undo func(...string)) error {
		for _, endpoint := range endpoints {
			svc := endpoint.Service
			qdisc := []string{"qdisc", "add", "dev", "eth0", "root", "handle", "1:", "prio", "bands", "3", "priomap"}
			for range 16 {
				qdisc = append(qdisc, "0")
			}
			if _, err := h.compose(ctx, append([]string{"exec", "-T", svc, "tc"}, qdisc...)...); err != nil {
				return err
			}
			undo("exec", "-T", svc, "tc", "qdisc", "del", "dev", "eth0", "root")
			if _, err := h.compose(ctx, append([]string{"exec", "-T", svc, "tc", "qdisc", "add", "dev", "eth0", "parent", "1:3", "handle", "30:", "netem"}, options...)...); err != nil {
				return err
			}
			for _, filter := range endpoint.Filters {
				args := append([]string{"exec", "-T", svc, "tc", "filter", "add", "dev", "eth0", "parent", "1:", "protocol", "ip", "prio", "1", "u32"}, filter...)
				args = append(args, "flowid", "1:3")
				if _, err := h.compose(ctx, args...); err != nil {
					return err
				}
			}
		}
		config := map[string]any{"scenario": h.selected, "path": path, "rtt": os.Getenv("RTT"), "loss": os.Getenv("LOSS"),
			"seed": os.Getenv("SEED"), "endpoints": endpoints, "options": options}
		data, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return err
		}
		if err := h.writeResult("network-impairment.json", string(data)); err != nil {
			return err
		}
		if _, err := h.event(ctx, "fault.applied", map[string]any{"Started": started, "Exited": time.Now().UTC()}); err != nil {
			return err
		}
		if err := h.waitEvent(ctx, "fault.release"); err != nil {
			return err
		}
		matched := make(map[string]bool)
		for _, endpoint := range endpoints {
			svc := endpoint.Service
			qdisc, err := h.compose(ctx, "exec", "-T", svc, "tc", "-j", "-s", "qdisc", "show", "dev", "eth0")
			if err != nil {
				return err
			}
			filters, err := h.compose(ctx, "exec", "-T", svc, "tc", "-j", "-s", "filter", "show", "dev", "eth0")
			if err != nil {
				return err
			}
			tcp, err := h.compose(ctx, "exec", "-T", svc, "ss", "-tin")
			if err != nil {
				return err
			}
			var entries []map[string]any
			if err := json.Unmarshal([]byte(qdisc), &entries); err != nil {
				return err
			}
			for _, entry := range entries {
				packets, _ := entry["packets"].(float64)
				if entry["kind"] == "netem" && packets > 0 {
					matched[svc] = true
				}
			}
			var filterValues []any
			if err := json.Unmarshal([]byte(filters), &filterValues); err != nil {
				return err
			}
			evidence, _ := json.MarshalIndent(map[string]any{"qdisc": entries, "filter": filterValues, "tcp": tcp}, "", "  ")
			if err := h.writeResult(svc+"-netem.json", string(evidence)); err != nil {
				return err
			}
		}
		for _, source := range sources {
			if !matched[source] {
				return errors.New("netem did not impair both directions of a visitor path")
			}
		}
		destinationMatched := false
		for _, destination := range destinations {
			destinationMatched = destinationMatched || matched[destination]
		}
		if !destinationMatched {
			return errors.New("netem did not impair both directions of a visitor path")
		}
		return nil
	})
}

func netemOptions(scenario, rtt, loss, rawSeed string) ([]string, error) {
	var result []string
	switch scenario {
	case "latency":
		switch rtt {
		case "20ms":
			result = []string{"delay", "10ms"}
		case "50ms":
			result = []string{"delay", "25ms"}
		case "100ms":
			result = []string{"delay", "50ms"}
		default:
			return nil, errors.New("RTT must be 20ms, 50ms, or 100ms")
		}
	case "packet-loss":
		if loss != "0.1" && loss != "1" {
			return nil, errors.New("LOSS must be 0.1 or 1 percent")
		}
		result = []string{"loss", "random", loss + "%"}
	default:
		return nil, errors.New("invalid impairment scenario")
	}
	seed, err := strconv.ParseUint(rawSeed, 10, 32)
	if err != nil {
		return nil, errors.New("invalid netem seed")
	}
	if seed != 0 {
		result = append(result, "seed", strconv.FormatUint(seed, 10))
	}
	return result, nil
}

func impairmentEndpoints(path string, addresses map[string]string, sources, destinations []string) ([]impairmentEndpoint, error) {
	port, protocols := "8443", []string{"6"}
	switch path {
	case "forwarding":
	case "publisher", "connector":
		port, protocols = "443", []string{"6", "17"}
	default:
		return nil, errors.New("invalid network path")
	}
	if len(sources) == 0 || len(destinations) == 0 {
		return nil, errors.New("network path requires planned sources and destinations")
	}
	for _, service := range slices.Concat(sources, destinations) {
		if addresses[service] == "" {
			return nil, fmt.Errorf("network path component %s has no address", service)
		}
	}
	endpoints := make([]impairmentEndpoint, 0, len(sources)+len(destinations))
	for _, source := range sources {
		endpoints = append(endpoints, impairmentEndpoint{Service: source, Filters: [][]string{}})
	}
	for _, destination := range destinations {
		reverse := impairmentEndpoint{Service: destination, Filters: [][]string{}}
		for index := range sources {
			for _, protocol := range protocols {
				endpoints[index].Filters = append(endpoints[index].Filters, []string{"match", "ip", "dst", addresses[destination],
					"match", "ip", "protocol", protocol, "0xff", "match", "ip", "dport", port, "0xffff"})
				reverse.Filters = append(reverse.Filters, []string{"match", "ip", "dst", addresses[sources[index]],
					"match", "ip", "protocol", protocol, "0xff", "match", "ip", "sport", port, "0xffff"})
			}
		}
		endpoints = append(endpoints, reverse)
	}
	return endpoints, nil
}

func (h *runtimeHarness) containerIP(ctx context.Context, service string) (string, error) {
	container := h.containers[service]
	if container == nil {
		return "", fmt.Errorf("runtime component %s is missing", service)
	}
	info, err := container.Inspect(ctx)
	if err != nil {
		return "", err
	}
	for _, network := range info.NetworkSettings.Networks {
		if network.IPAddress.IsValid() {
			return network.IPAddress.String(), nil
		}
	}
	return "", fmt.Errorf("%s has no IPv4 address", service)
}

func (h *runtimeHarness) waitEvent(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	for {
		data, err := h.event(ctx, name, nil)
		if err != nil {
			return err
		}
		if len(data) != 0 {
			return nil
		}
		if err := sleepRuntime(ctx, 250*time.Millisecond); err != nil {
			return err
		}
	}
}

func (h *runtimeHarness) writeResult(name, value string) error {
	return os.WriteFile(filepath.Join(h.results, name), []byte(value), 0o644)
}

func sleepRuntime(ctx context.Context, delay time.Duration) error {
	select {
	case <-time.After(delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
