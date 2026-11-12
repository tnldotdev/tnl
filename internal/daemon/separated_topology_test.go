package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"testing"

	"go.yaml.in/yaml/v3"
)

// setup owns the concrete compose membership and workload assignments. all
// processes, including the outer runner, read its saved projections rather
// than selecting their own topology from workload flags.
func newSeparatedPlan(workload, scenario, path string, count int, ha bool) (map[string][]string, error) {
	if workload != "public-url" && workload != "connect" && workload != "postgres" {
		return nil, fmt.Errorf("invalid runtime workload %q", workload)
	}
	if workload == "postgres" && count != 1 || workload != "postgres" && (count < 4 || count > 10000) {
		return nil, fmt.Errorf("invalid runtime publication count %d for %s", count, workload)
	}
	if !slices.Contains([]string{"relay-restart", "control-restart", "relay-kill", "forwarding-blackhole", "publisher-blackhole", "udp-fallback", "latency", "packet-loss"}, scenario) {
		return nil, fmt.Errorf("invalid runtime scenario %q", scenario)
	}
	if scenario == "control-restart" && !ha {
		return nil, fmt.Errorf("control restart requires the two-control topology")
	}
	if path != "forwarding" && path != "publisher" && !(path == "connector" && workload == "connect") {
		return nil, fmt.Errorf("invalid runtime network path %q", path)
	}
	p := map[string][]string{
		"controls": {"control-a"}, "ingresses": {"ingress-a"},
		"relays": {"relay-a", "relay-b"}, "visitors": {"visitor-1"},
	}
	if ha {
		p["controls"] = append(p["controls"], "control-b")
		p["ingresses"] = append(p["ingresses"], "ingress-b")
	}
	if scenario == "control-restart" {
		p["relays"] = append(p["relays"], "relay-a-2", "relay-b-2")
	}
	for _, relay := range p["relays"] {
		service, instance := relay, "1"
		if relay == "relay-a-2" || relay == "relay-b-2" {
			service, instance = relay[:len(relay)-2], "2"
		}
		p["relay-service."+relay] = []string{service}
		p["relay-id."+relay] = []string{service + "-" + instance}
	}
	if workload == "postgres" {
		p["targets"] = []string{"postgres-target"}
	} else {
		// even a four-publication smoke run uses all four visitor sources.
		p["visitors"] = append(p["visitors"], "visitor-2", "visitor-3", "visitor-4")
	}
	for shard := range min(4, (count+1)/2) {
		publisher, app := "publishers", "app"
		if shard != 0 {
			publisher += "-" + strconv.Itoa(shard+1)
			app += "-" + strconv.Itoa(shard+1)
		}
		p["publishers"] = append(p["publishers"], publisher)
		if workload != "postgres" {
			p["apps"] = append(p["apps"], app)
			p["app-publisher."+app] = []string{publisher}
		}
		// each shard owns a quic/tcp pair, wrapping after four shards. keep
		// this allocation when smaller runs omit the unused later shards.
		for index := 2 * shard; index < count; index += 8 {
			p["publisher-indexes."+publisher] = append(p["publisher-indexes."+publisher], strconv.Itoa(index))
			if index+1 < count {
				p["publisher-indexes."+publisher] = append(p["publisher-indexes."+publisher], strconv.Itoa(index+1))
			}
		}
	}
	join := func(groups ...[]string) []string { return slices.Concat(groups...) }
	p["servers"] = join(p["controls"], p["ingresses"], p["relays"])
	p["ready"] = join(p["servers"], p["apps"], []string{"pebble"})
	p["components"] = join(p["servers"], p["publishers"], p["visitors"], p["apps"], []string{"pebble"})
	p["start"] = join(p["components"], p["targets"], []string{"dns", "coordinator"})
	p["resources"] = join(p["components"], p["targets"], []string{"postgres", "coordinator"})
	p["services"] = join([]string{"postgres"}, p["start"])
	p["stop-visitors"] = slices.Clone(p["visitors"])
	p["stop-publishers"] = join(p["apps"], p["publishers"])
	p["stop-servers"] = join(p["ingresses"], p["relays"])
	p["stop-controls"] = slices.Clone(p["controls"])
	p["stop-support"] = join([]string{"pebble", "dns", "coordinator"}, p["targets"], []string{"postgres"})
	switch scenario {
	case "relay-restart", "relay-kill":
		p["fault-targets"] = p["relays"][:1]
	case "control-restart":
		p["fault-targets"] = p["controls"][:1]
	case "forwarding-blackhole", "publisher-blackhole", "udp-fallback":
		p["fault-sources"], p["fault-destinations"] = p["publishers"], p["relays"][:1]
		if scenario == "forwarding-blackhole" {
			p["fault-sources"] = p["ingresses"]
		}
		if scenario == "udp-fallback" {
			p["fault-destinations"] = p["relays"]
		}
		p["fault-targets"] = join(p["fault-sources"], p["fault-destinations"])
	case "latency", "packet-loss":
		p["fault-sources"], p["fault-destinations"] = p["ingresses"], p["relays"]
		if path == "publisher" {
			p["fault-sources"] = p["publishers"]
		}
		if path == "connector" {
			p["fault-sources"] = p["visitors"]
		}
		p["fault-targets"] = join(p["fault-sources"], p["fault-destinations"])
	}
	return p, nil
}

var readSeparatedPlan = sync.OnceValues(func() (map[string][]string, error) {
	data, err := os.ReadFile("/results/runtime-plan.json")
	if err != nil {
		return nil, err
	}
	var plan map[string][]string
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, err
	}
	if len(plan["services"]) == 0 {
		return nil, fmt.Errorf("runtime plan has no services")
	}
	return plan, nil
})

func separatedPlan(t *testing.T) map[string][]string {
	t.Helper()
	plan, err := readSeparatedPlan()
	if err != nil {
		t.Fatalf("read runtime plan: %v", err)
	}
	return plan
}

func separatedNames(projection string) []string {
	plan, err := readSeparatedPlan()
	if err != nil {
		panic(fmt.Errorf("read runtime plan: %w", err))
	}
	// callers may append to their projection without changing the shared plan.
	return slices.Clone(plan[projection])
}

func separatedPublisherIndexes(t *testing.T, shard int) []int {
	t.Helper()
	plan := separatedPlan(t)
	var indexes []int
	for _, value := range plan["publisher-indexes."+plan["publishers"][shard]] {
		index, err := strconv.Atoi(value)
		if err != nil {
			t.Fatal(err)
		}
		indexes = append(indexes, index)
	}
	return indexes
}

func TestSeparatedRuntimePlan(t *testing.T) {
	for _, test := range []struct {
		workload                            string
		count                               int
		publishers, apps, visitors, targets []string
	}{
		{"public-url", 4, []string{"publishers", "publishers-2"}, []string{"app", "app-2"}, []string{"visitor-1", "visitor-2", "visitor-3", "visitor-4"}, nil},
		{"connect", 4, []string{"publishers", "publishers-2"}, []string{"app", "app-2"}, []string{"visitor-1", "visitor-2", "visitor-3", "visitor-4"}, nil},
		{"public-url", 5, []string{"publishers", "publishers-2", "publishers-3"}, []string{"app", "app-2", "app-3"}, []string{"visitor-1", "visitor-2", "visitor-3", "visitor-4"}, nil},
		{"public-url", 8, []string{"publishers", "publishers-2", "publishers-3", "publishers-4"}, []string{"app", "app-2", "app-3", "app-4"}, []string{"visitor-1", "visitor-2", "visitor-3", "visitor-4"}, nil},
		{"postgres", 1, []string{"publishers"}, nil, []string{"visitor-1"}, []string{"postgres-target"}},
	} {
		for _, ha := range []bool{false, true} {
			for _, scenario := range []string{"relay-restart", "control-restart", "relay-kill", "forwarding-blackhole", "publisher-blackhole", "udp-fallback", "latency", "packet-loss"} {
				plan, err := newSeparatedPlan(test.workload, scenario, "forwarding", test.count, ha)
				if scenario == "control-restart" && !ha {
					if err == nil {
						t.Fatal("accepted control restart without HA")
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				controls, ingresses, relays := []string{"control-a"}, []string{"ingress-a"}, []string{"relay-a", "relay-b"}
				if ha {
					controls = append(controls, "control-b")
					ingresses = append(ingresses, "ingress-b")
				}
				if scenario == "control-restart" {
					relays = append(relays, "relay-a-2", "relay-b-2")
				}
				want := slices.Concat(controls, ingresses, relays, test.publishers, test.visitors, test.apps, []string{"pebble"}, test.targets, []string{"dns", "coordinator"})
				if !slices.Equal(plan["start"], want) {
					t.Fatalf("%s/%d ha=%t %s: start=%v, want %v", test.workload, test.count, ha, scenario, plan["start"], want)
				}
				components := slices.Concat(controls, ingresses, relays, test.publishers, test.visitors, test.apps, []string{"pebble"})
				for key, want := range map[string][]string{
					"controls": controls, "ingresses": ingresses, "relays": relays,
					"publishers": test.publishers, "apps": test.apps, "visitors": test.visitors, "targets": test.targets,
					"components":    components,
					"ready":         slices.Concat(controls, ingresses, relays, test.apps, []string{"pebble"}),
					"resources":     slices.Concat(components, test.targets, []string{"postgres", "coordinator"}),
					"stop-controls": controls,
					"stop-support":  slices.Concat([]string{"pebble", "dns", "coordinator"}, test.targets, []string{"postgres"}),
				} {
					if !slices.Equal(plan[key], want) {
						t.Fatalf("%s: %v, want %v", key, plan[key], want)
					}
				}
				stopped := slices.Concat(plan["stop-visitors"], plan["stop-publishers"], plan["stop-servers"], plan["stop-controls"], plan["stop-support"])
				slices.Sort(stopped)
				services := slices.Sorted(slices.Values(plan["services"]))
				if !slices.Equal(stopped, services) || len(slices.Compact(stopped)) != len(services) {
					t.Fatalf("shutdown does not cover each service once: %v / %v", stopped, services)
				}
				for _, projection := range []string{"ready", "components", "resources", "controls", "ingresses", "relays", "publishers", "visitors", "apps", "targets", "fault-targets", "fault-sources", "fault-destinations"} {
					for _, name := range plan[projection] {
						if !slices.Contains(services, name) {
							t.Fatalf("%s contains absent service %s", projection, name)
						}
					}
				}
			}
		}
	}
}

func TestSeparatedFaultTargets(t *testing.T) {
	for _, test := range []struct {
		workload, scenario, path string
		sources, destinations    []string
	}{
		{"public-url", "relay-restart", "forwarding", nil, []string{"relay-a"}},
		{"public-url", "relay-kill", "forwarding", nil, []string{"relay-a"}},
		{"public-url", "control-restart", "forwarding", nil, []string{"control-a"}},
		{"public-url", "forwarding-blackhole", "forwarding", []string{"ingress-a", "ingress-b"}, []string{"relay-a"}},
		{"public-url", "publisher-blackhole", "publisher", []string{"publishers", "publishers-2"}, []string{"relay-a"}},
		{"public-url", "udp-fallback", "publisher", []string{"publishers", "publishers-2"}, []string{"relay-a", "relay-b"}},
		{"public-url", "latency", "forwarding", []string{"ingress-a", "ingress-b"}, []string{"relay-a", "relay-b"}},
		{"public-url", "packet-loss", "publisher", []string{"publishers", "publishers-2"}, []string{"relay-a", "relay-b"}},
		{"connect", "latency", "connector", []string{"visitor-1", "visitor-2", "visitor-3", "visitor-4"}, []string{"relay-a", "relay-b"}},
		{"connect", "packet-loss", "connector", []string{"visitor-1", "visitor-2", "visitor-3", "visitor-4"}, []string{"relay-a", "relay-b"}},
	} {
		plan, err := newSeparatedPlan(test.workload, test.scenario, test.path, 4, true)
		if err != nil {
			t.Fatal(err)
		}
		want := slices.Concat(test.sources, test.destinations)
		if !slices.Equal(plan["fault-targets"], want) || !slices.Equal(plan["fault-sources"], test.sources) {
			t.Fatalf("%s/%s targets=%v sources=%v, want %v / %v", test.scenario, test.path, plan["fault-targets"], plan["fault-sources"], want, test.sources)
		}
		for _, target := range want {
			if !slices.Contains(plan["services"], target) {
				t.Fatal("fault targets absent service", target)
			}
		}
	}
}

func TestSeparatedComposeMatchesPlan(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../tests/integration/fixtures/separated-stack/compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Services map[string]struct {
			NetworkMode string   `yaml:"network_mode"`
			Profiles    []string `yaml:"profiles"`
			Networks    map[string]struct {
				Aliases []string `yaml:"aliases"`
			} `yaml:"networks"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{"build": true, "setup": true}
	for _, test := range []struct {
		workload, scenario string
		count              int
	}{{"public-url", "control-restart", 8}, {"postgres", "relay-restart", 1}} {
		plan, err := newSeparatedPlan(test.workload, test.scenario, "forwarding", test.count, true)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range plan["services"] {
			service, ok := fixture.Services[name]
			if !ok {
				t.Fatal("planned service absent from Compose", name)
			}
			if len(service.Profiles) != 0 {
				t.Fatal("Compose profile selects membership instead of the plan", name)
			}
			used[name] = true
		}
		for _, app := range plan["apps"] {
			if want := "service:" + plan["app-publisher."+app][0]; fixture.Services[app].NetworkMode != want {
				t.Fatalf("%s namespace=%s, want %s", app, fixture.Services[app].NetworkMode, want)
			}
		}
		identities := make(map[string]bool)
		for _, relay := range plan["relays"] {
			id, service := plan["relay-id."+relay][0], plan["relay-service."+relay][0]
			if identities[id] {
				t.Fatal("duplicate planned relay identity", id)
			}
			identities[id] = true
			if !slices.Contains(fixture.Services[relay].Networks["default"].Aliases, service+".split.integration.test") {
				t.Fatal("relay service alias differs from its assignment", relay, service)
			}
		}
	}
	for name := range fixture.Services {
		if !used[name] {
			t.Fatal("unowned Compose component", name)
		}
	}
}

func TestSeparatedPublisherAssignments(t *testing.T) {
	for _, total := range []int{1, 4, 5, 6, 7, 8, 17, 64, 3000, 10000} {
		workload := "public-url"
		if total == 1 {
			workload = "postgres"
		}
		plan, err := newSeparatedPlan(workload, "relay-restart", "forwarding", total, true)
		if err != nil {
			t.Fatal(err)
		}
		seen := make([]bool, total)
		for shard, publisher := range plan["publishers"] {
			indexes := plan["publisher-indexes."+publisher]
			firstWindow := 0
			for _, value := range indexes {
				index, err := strconv.Atoi(value)
				if err != nil || index < 0 || index >= total || seen[index] {
					t.Fatalf("total=%d shard=%d invalid index %q", total, shard, value)
				}
				if index/2%4 != shard {
					t.Fatalf("index %d moved shards", index)
				}
				seen[index] = true
				if index < 64 {
					firstWindow++
				}
			}
			if total >= 8 && (indexes[0] != strconv.Itoa(2*shard) || indexes[1] != strconv.Itoa(2*shard+1)) {
				t.Fatal("publisher lost mixed transport pair", indexes)
			}
			if total >= 64 && firstWindow != 16 {
				t.Fatal("publisher lost first-window allocation", firstWindow)
			}
		}
		for index, found := range seen {
			if !found {
				t.Fatalf("total=%d missing index=%d", total, index)
			}
		}
	}
}
