package ingress

import (
	"testing"
	"time"

	routebackend "github.com/tnldotdev/tnl/internal/ingress/backend"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

func TestPublisherPoolReservesHealthyCapacityForEachNewConnection(t *testing.T) {
	server, _ := startIngress(t, Config{})
	limits := trafficlimits.Default()
	limits.Connections = 1
	runs := []PublicURL{
		{ID: "saved", PublishRunID: "publisher-a", Traffic: &limits, Backends: []routebackend.Backend{&singleBackend{}}},
		{ID: "saved", PublishRunID: "publisher-b", Traffic: &limits, Backends: []routebackend.Backend{&singleBackend{}}},
	}
	first, releaseFirst, reason := server.selectPoolRun(runs)
	if reason != LookupCurrent {
		t.Fatal(reason)
	}
	defer releaseFirst()
	second, releaseSecond, reason := server.selectPoolRun(runs)
	if reason != LookupCurrent || second.PublishRunID == first.PublishRunID {
		t.Fatal("new connection selected a full publisher")
	}
	defer releaseSecond()
	if _, release, reason := server.selectPoolRun(runs); reason != LookupNoBackends || release != nil {
		t.Fatal("full pool admitted another connection")
	}
	releaseFirst()
	releaseFirst()
	next, releaseNext, reason := server.selectPoolRun(runs)
	if reason != LookupCurrent || next.PublishRunID != first.PublishRunID {
		t.Fatal("closed connection did not release exact-run capacity")
	}
	defer releaseNext()
	if second.PublishRunID == next.PublishRunID {
		t.Fatal("established stream migrated during selection")
	}
}

func TestPrivateRoutingPoolTombstoneKeepsSiblingRun(t *testing.T) {
	_, control, _, _, _, _ := privateTestSetup(t)
	first := control.projection
	second := clonePrivateProjection(first)
	run := privateTestID(t, "psrun_")
	number := int64(2)
	second.PrivateRunId = &run
	second.RunNumber = &number
	second.Revision = 2
	now := time.Now()
	var table PrivateRoutingTable
	if err := table.ApplySnapshot(ingressv1.PrivateServiceSnapshot{Revision: 2, Entries: []ingressv1.PrivateServiceProjection{first, second}}, now); err != nil {
		t.Fatal(err)
	}
	tombstone := clonePrivateProjection(first)
	tombstone.Kind = ingressv1.Tombstone
	tombstone.ConnectedRelays = nil
	tombstone.Revision = 3
	if err := table.ApplyEvents(2, ingressv1.PrivateServiceSnapshot{Revision: 3, Entries: []ingressv1.PrivateServiceProjection{tombstone}}, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := table.Lookup(first.PrivateServiceId, *first.PrivateRunId, *first.RunNumber, now); ok {
		t.Fatal("tombstoned run remains routable")
	}
	if _, ok := table.Lookup(second.PrivateServiceId, run, number, now); !ok {
		t.Fatal("run tombstone deleted pool sibling")
	}
}
