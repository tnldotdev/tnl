package ingress

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func restorationCloneSnapshot(t *testing.T, snapshot ingressv1.IngressServices) ingressv1.IngressServices {
	t.Helper()
	wire, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var clone ingressv1.IngressServices
	if err := json.Unmarshal(wire, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func restorationIPPolicy(t *testing.T, prefixes ...string) *controlv1.VisitorPolicyIP {
	t.Helper()
	key := [32]byte{2}
	policy := &controlv1.VisitorPolicyIP{Key: slices.Clone(key[:])}
	for _, prefix := range prefixes {
		entry, err := ippolicy.Hash(key, netip.MustParsePrefix(prefix))
		if err != nil {
			t.Fatal(err)
		}
		policy.Prefixes = append(policy.Prefixes, controlv1.HashedIPPrefix{
			Family: controlv1.HashedIPPrefixFamily(entry.Family), PrefixLength: entry.Bits, Digest: entry.Digest})
	}
	return policy
}

type restorationRouteView struct {
	run       ingressv1.IngressServiceRun
	source    tunnelv1.VisitorSourceAuthority
	sourceKey [32]byte
	traffic   TrafficLimits
	until     time.Time
	allowed   bool
}

func restorationView(t *testing.T, route *serviceRoute) restorationRouteView {
	t.Helper()
	clone := restorationCloneSnapshot(t, ingressv1.IngressServices{Runs: []ingressv1.IngressServiceRun{route.run}})
	source := route.source
	source.MAC = slices.Clone(source.MAC)
	return restorationRouteView{run: clone.Runs[0], source: source, sourceKey: route.sourceKey,
		traffic: route.traffic, until: route.until, allowed: route.ip != nil && route.ip.Allows(netip.MustParseAddr("192.0.2.4"))}
}

func restorationOwnedSnapshot(t *testing.T) (ingressv1.IngressLease, ingressv1.IngressServices) {
	t.Helper()
	lease, snapshot := serviceRoutingFixture(t)
	first := &snapshot.Runs[0]
	first.RecoveryEpisodeId = new(int64(1))
	first.Traffic.TotalConnections, first.Traffic.TotalUploadBytes, first.Traffic.TotalDownloadBytes =
		new(int64(128)), new(int64(4096)), new(int64(8192))
	first.Ip = restorationIPPolicy(t, "192.0.2.0/24")
	second := restorationCloneSnapshot(t, snapshot).Runs[0]
	second.ServiceRunId, second.RunNumber, second.Hostname = publicServiceTestID(t, "srun_"), 2, "second.example"
	restorationDelegate(t, lease, &second, snapshot.ObservedAt, snapshot.ValidUntil)
	snapshot.Runs = append(snapshot.Runs, second)
	return lease, snapshot
}

func TestServiceSnapshotRestorationOwnsInputsAndLookupOutputs(t *testing.T) {
	for _, boundary := range []string{"input", "lookup"} {
		t.Run(boundary, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				lease, snapshot := restorationOwnedSnapshot(t)
				routing := NewServiceRouting()
				defer routing.Close()
				if err := routing.apply(time.Now(), lease, snapshot); err != nil {
					t.Fatal(err)
				}
				want := make(map[string]restorationRouteView)
				for _, run := range snapshot.Runs {
					want[run.Hostname] = restorationView(t, routing.lookup(run.Hostname, 443, lease, time.Now())[0])
				}
				for index := range snapshot.Runs {
					input := &snapshot.Runs[index]
					mutated := input
					if boundary == "lookup" {
						route := routing.lookup(input.Hostname, 443, lease, time.Now())[0]
						mutated = &route.run
						route.source.MAC[0] ^= 0xff
						route.sourceKey[0] ^= 0xff
					} else {
						input.SourceAuthority[0] ^= 0xff
						input.SourceKey[0] ^= 0xff
						input.Ip.Key[0] ^= 0xff
						input.Ip.Prefixes[0].Digest = "changed"
					}
					mutated.ConnectedRelays[0].RelayId = "changed"
					*mutated.RecoveryEpisodeId = 99
					*mutated.Traffic.TotalConnections = 99
					*mutated.Traffic.TotalUploadBytes = 99
					*mutated.Traffic.TotalDownloadBytes = 99
				}
				for hostname, expected := range want {
					got := routing.lookup(hostname, 443, lease, time.Now())
					if len(got) != 1 || !reflect.DeepEqual(restorationView(t, got[0]), expected) {
						t.Error("caller mutation changed retained snapshot state at " + boundary + " boundary for " + hostname)
					}
				}
			})
		})
	}
}

func TestServiceSnapshotRestorationRejectsWholeInvalidUpdateAndKeepsHeldViews(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, snapshot := restorationOwnedSnapshot(t)
		routing := NewServiceRouting()
		defer routing.Close()
		if err := routing.apply(time.Now(), lease, snapshot); err != nil {
			t.Fatal(err)
		}
		routing.mu.Lock()
		heldRuns, heldEndpoints := routing.runs, routing.endpoints
		started, observed := routing.startedAt, routing.observedAt
		routing.mu.Unlock()
		expected := make(map[string]restorationRouteView)
		for id, route := range heldRuns {
			expected[id] = restorationView(t, route)
		}
		restorationAdvance(time.Second)
		update := restorationCloneSnapshot(t, snapshot)
		update.ObservedAt, update.ValidUntil = time.Now(), time.Now().Add(visitortoken.PolicyLifetime)
		first := &update.Runs[0]
		first.EndpointRevision++
		first.ValidUntil = update.ValidUntil
		first.Ip = restorationIPPolicy(t, "198.51.100.0/24")
		restorationDelegate(t, lease, first, update.ObservedAt, update.ValidUntil)
		update.Runs[1].SourceKey = nil
		if err := routing.apply(time.Now(), lease, update); err == nil {
			t.Fatal("valid first run leaked through an invalid second run")
		}
		routing.mu.Lock()
		unchanged := routing.startedAt.Equal(started) && routing.observedAt.Equal(observed) && len(routing.runs) == 2 && len(routing.sourceCounters) == 2
		routing.mu.Unlock()
		if !unchanged {
			t.Error("rejected full snapshot advanced ownership or source counters")
		}
		for id, route := range heldRuns {
			if !reflect.DeepEqual(restorationView(t, route), expected[id]) ||
				!reflect.DeepEqual(restorationView(t, routing.lookup(route.run.Hostname, 443, lease, time.Now())[0]), expected[id]) {
				t.Error("rejected snapshot changed an installed or held run")
			}
		}
		// a successful whole replacement may not mutate readers holding the old
		// outer map, endpoint buckets, or run objects.
		update.Runs[1] = restorationCloneSnapshot(t, snapshot).Runs[1]
		update.Runs[1].ValidUntil = update.ValidUntil
		third := restorationCloneSnapshot(t, snapshot).Runs[0]
		third.ServiceRunId, third.RunNumber, third.Hostname = publicServiceTestID(t, "srun_"), 3, "new.example"
		third.ValidUntil = update.ValidUntil
		restorationDelegate(t, lease, &third, update.ObservedAt, update.ValidUntil)
		update.Runs = append(update.Runs, third)
		if err := routing.apply(time.Now(), lease, update); err != nil {
			t.Fatal(err)
		}
		if len(heldRuns) != 2 || len(heldEndpoints) != 2 {
			t.Error("replacement mutated a previously published outer map")
		}
		for id, route := range heldRuns {
			if !reflect.DeepEqual(restorationView(t, route), expected[id]) {
				t.Error("replacement mutated a held run")
			}
			bucket := heldEndpoints[serviceEndpoint{hostname: route.run.Hostname, port: 443}]
			if len(bucket) != 1 || !reflect.DeepEqual(restorationView(t, bucket[0]), expected[id]) {
				t.Error("replacement mutated a held hostname bucket")
			}
		}
	})
}

func TestServiceSnapshotRestorationRetains256HashedIPv6Prefixes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, snapshot := serviceRoutingFixture(t)
		prefixes := make([]string, 256)
		for index := range 256 {
			prefixes[index] = fmt.Sprintf("2001:db8:%x::/48", index)
		}
		snapshot.Runs[0].Ip = restorationIPPolicy(t, prefixes...)
		routing := NewServiceRouting()
		defer routing.Close()
		if err := routing.apply(time.Now(), lease, snapshot); err != nil {
			t.Fatal(err)
		}
		route := routing.lookup("route.example", 443, lease, time.Now())[0]
		if len(snapshot.Runs[0].Ip.Prefixes) != 256 || route.ip == nil ||
			!route.ip.Allows(netip.MustParseAddr("2001:db8:ff::1")) ||
			route.ip.Allows(netip.MustParseAddr("2001:db8:100::1")) {
			t.Fatal("large installed IPv6 policy lost the last accepted or first rejected /48")
		}
		for index := range 256 {
			if !route.ip.Allows(netip.MustParseAddr(fmt.Sprintf("2001:db8:%x::1", index))) {
				t.Fatal("installation dropped an allowed IPv6 /48", index)
			}
		}
		release, err := routing.bind(route, netip.MustParseAddr("2001:db8:ff::1"), func() {})
		if err != nil {
			t.Fatal("last installed IPv6 prefix was not usable", err)
		}
		release()
		if release, err := routing.bind(route, netip.MustParseAddr("2001:db8:100::1"), func() {}); err == nil {
			release()
			t.Fatal("first absent IPv6 prefix acquired routing authority")
		}
	})
}
