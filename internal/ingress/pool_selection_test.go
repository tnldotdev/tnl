package ingress

import (
	"testing"

	ingressbackend "github.com/tnldotdev/tnl/internal/ingress/backend"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

func TestPublisherPoolReservesHealthyCapacityForEachNewConnection(t *testing.T) {
	server, _ := startIngress(t, Config{})
	limits := trafficlimits.Default()
	limits.Connections = 1
	runs := []PublicURL{
		{ID: "saved", PublishRunID: "publisher-a", Traffic: &limits, Backends: []ingressbackend.Backend{&singleBackend{}}},
		{ID: "saved", PublishRunID: "publisher-b", Traffic: &limits, Backends: []ingressbackend.Backend{&singleBackend{}}},
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
