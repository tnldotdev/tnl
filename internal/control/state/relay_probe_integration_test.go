package state

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/region"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationRelayProbeCandidatesExcludeDrainingAndExpiredServices(t *testing.T) {
	database, now, _, leases := newPublishRunPrerequisites(t)
	check := func(at time.Time, want int) []RelayProbeCandidate {
		t.Helper()
		candidates, err := database.ListRelayProbeCandidates(t.Context(), at)
		if err != nil || len(candidates) != want {
			t.Fatalf("candidate inventory at %s: %v %v", at, candidates, err)
		}
		return candidates
	}
	for _, candidate := range check(now, 2) {
		lease, found := leases[candidate.ServiceID]
		if !found || candidate.Region != lease.Region || candidate.Address != lease.RelayAddress || candidate.TLSServerName != lease.TLSServerName {
			t.Fatalf("candidate differs from its live relay lease: %+v", candidate)
		}
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.relay_leases SET draining=true WHERE relay_service_id=$1`, "placement-0"); err != nil {
		t.Fatal(err)
	}
	check(now, 1)
	check(now.Add(2*time.Hour), 0)
}

func TestIntegrationRelayProbeCandidatesReserveTwoPerRegion(t *testing.T) {
	database, now, _, _ := newPublishRunPrerequisites(t)
	for _, entry := range []struct {
		id   string
		code region.Code
	}{{"a-sjc", "sjc"}, {"b-sjc", "sjc"}, {"c-sjc", "sjc"}, {"z-ord", "ord"}, {"zz-ord", "ord"}} {
		if _, err := database.RegisterRelay(t.Context(), RelayRegistration{RelayServiceID: entry.id, RelayID: entry.id,
			RelayRunID: entry.id + "-run", Region: entry.code, ProtocolVersion: tunnelv1.Version,
			RelayAddress: entry.id + ".example.test:443", TLSServerName: entry.id + ".example.test",
			InternalRelayAddress: entry.id + ".internal:9443", ConnectionCapacity: 4, StreamCapacity: 4}, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	candidates, err := database.ListRelayProbeCandidates(t.Context(), now)
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[region.Code]int)
	for _, candidate := range candidates {
		counts[candidate.Region]++
	}
	if counts["sjc"] != 2 || counts["ord"] != 2 || counts["local"] != 2 || len(candidates) != 6 {
		t.Fatal("inventory dropped a distant region or leaked extra probes", counts)
	}
}
