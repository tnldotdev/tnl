package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
		h.intentional.Store(true)
		if _, err := h.compose(ctx, "kill", "--signal", "SIGKILL", "relay-a"); err != nil {
			return err
		}
		state, err := h.containers["relay-a"].State(ctx)
		if err != nil || state.Running || state.ExitCode != 137 {
			return fmt.Errorf("relay kill did not produce the expected process exit: %v", err)
		}
		if _, err := h.event(ctx, "fault.applied", map[string]any{"Started": started, "Exited": time.Now().UTC()}); err != nil {
			return err
		}
		if err := sleepRuntime(ctx, 31*time.Second); err != nil {
			return err
		}
		if _, err := h.compose(ctx, "start", "relay-a"); err != nil {
			return err
		}
		h.intentional.Store(false)
	case "forwarding-blackhole", "publisher-blackhole", "udp-fallback":
		if err := h.blackhole(ctx, started); err != nil {
			return err
		}
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

func (h *runtimeHarness) blackhole(ctx context.Context, started time.Time) error {
	sources := h.activePublish
	if h.selected == "forwarding-blackhole" {
		sources = h.ingresses
	}
	relays, protocols := []string{"relay-a"}, []string{"tcp"}
	if h.selected == "udp-fallback" {
		relays, protocols = []string{"relay-a", "relay-b"}, []string{"udp"}
	} else if h.selected == "publisher-blackhole" {
		protocols = []string{"tcp", "udp"}
	}
	return h.withFaultCleanup(ctx, func(undo func(...string)) error {
		for _, source := range sources {
			for _, relay := range relays {
				address, err := h.containerIP(ctx, relay)
				if err != nil {
					return err
				}
				for _, protocol := range protocols {
					port := "443"
					if h.selected == "forwarding-blackhole" {
						port = "8443"
					}
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
			for _, publisher := range runtimePublishers {
				sockets, err := h.compose(ctx, "exec", "-T", publisher, "ss", "-H", "-uan")
				if err != nil {
					return err
				}
				if err := h.writeResult(publisher+"-udp-sockets-after-fallback.txt", sockets); err != nil {
					return err
				}
				for _, line := range strings.Split(strings.TrimSpace(sockets), "\n") {
					fields := strings.Fields(line)
					if len(fields) > 3 && !strings.HasPrefix(fields[3], "127.0.0.11:") {
						return fmt.Errorf("%s retained an abandoned QUIC socket", publisher)
					}
				}
			}
			if _, err := h.event(ctx, "udp.cleaned", true); err != nil {
				return err
			}
		}
		if err := h.waitEvent(ctx, "fault.release"); err != nil {
			return err
		}
		for _, source := range sources {
			counters, err := h.compose(ctx, "exec", "-T", source, "iptables", "-L", "OUTPUT", "-n", "-v", "-x")
			if err != nil {
				return err
			}
			if err := h.writeResult(h.selected+"-"+source+"-counters.txt", counters); err != nil {
				return err
			}
			if err := validateBlackholeCounters(counters, len(relays)*len(protocols)); err != nil {
				return err
			}
		}
		return nil
	})
}

func validateBlackholeCounters(counters string, expected int) error {
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
	if path != "forwarding" && path != "publisher" && !(path == "connector" && os.Getenv("RUNTIME_WORKLOAD") == "connect") {
		return errors.New("invalid network path")
	}
	options, err := netemOptions(h.selected, os.Getenv("RTT"), os.Getenv("LOSS"), os.Getenv("SEED"))
	if err != nil {
		return err
	}
	addresses := make(map[string]string)
	visitors := []string{"visitor-1", "visitor-2", "visitor-3", "visitor-4"}
	for _, service := range append(append(append([]string{}, h.ingresses...), visitors...), append(h.activePublish, "relay-a", "relay-b")...) {
		addresses[service], err = h.containerIP(ctx, service)
		if err != nil {
			return err
		}
	}
	sources, destinations := h.ingresses, []string{"relay-a", "relay-b"}
	if path == "publisher" {
		sources = h.activePublish
	}
	if path == "connector" {
		sources = visitors
	}
	endpoints, err := impairmentEndpoints(path, addresses, h.ingresses, h.activePublish, visitors)
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

func impairmentEndpoints(path string, addresses map[string]string, ingresses, publishers, visitors []string) ([]impairmentEndpoint, error) {
	sources, destinations, port, protocols := ingresses, []string{"relay-a", "relay-b"}, "8443", []string{"6"}
	if path == "publisher" {
		sources, port, protocols = publishers, "443", []string{"6", "17"}
	} else if path == "connector" {
		sources, port, protocols = visitors, "443", []string{"6", "17"}
	} else if path != "forwarding" {
		return nil, errors.New("invalid network path")
	}
	return targetedImpairmentEndpoints(addresses, sources, destinations, port, protocols)
}

func targetedImpairmentEndpoints(addresses map[string]string, sources, destinations []string, port string, protocols []string) ([]impairmentEndpoint, error) {
	if len(sources) == 0 || len(destinations) == 0 {
		return nil, errors.New("network path requires a source")
	}
	endpoints := make([]impairmentEndpoint, 0, len(sources)+len(destinations))
	for _, source := range sources {
		endpoints = append(endpoints, impairmentEndpoint{Service: source, Filters: [][]string{}})
	}
	for _, relay := range destinations {
		reverse := impairmentEndpoint{Service: relay, Filters: [][]string{}}
		for index := range sources {
			for _, protocol := range protocols {
				endpoints[index].Filters = append(endpoints[index].Filters, []string{"match", "ip", "dst", addresses[relay],
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
