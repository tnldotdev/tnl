package visitorpolicy

import (
	"crypto/sha256"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
)

func TestMaximumAllocationKeysAndWireBudget(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 123456789, time.UTC)
	body, _ := Maximum(t, now)
	seen := make(map[[32]byte]struct{}, len(body.Policy.StreamAllocations))
	maximumFixtureAllocation := 0
	for _, allocation := range body.Policy.StreamAllocations {
		if len(allocation.ReservationKey) != 32 {
			t.Fatal("maximum fixture omitted a valid allocation key")
		}
		key := [32]byte(allocation.ReservationKey)
		if key != sha256.Sum256([]byte(allocation.Id)) {
			t.Fatal("fixture allocation key is not deterministic")
		}
		if _, duplicate := seen[key]; duplicate {
			t.Fatal("fixture reused a key across allocations")
		}
		seen[key] = struct{}{}
		raw, err := json.Marshal(allocation)
		if err != nil {
			t.Fatal(err)
		}
		maximumFixtureAllocation = max(maximumFixtureAllocation, len(raw)+1)
	}
	if len(seen) != 2048 {
		t.Fatal("fixture lost its maximum allocation count")
	}
	update, err := visitorlease.Decode(body)
	if err != nil {
		t.Fatal("maximum fixture is not a valid decoder base", err)
	}
	lease, err := visitorlease.New(update.View.Scope, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := lease.Apply(lease.Begin(), update); err != nil {
		t.Fatal("maximum fixture is not an installable base", err)
	}

	// overbound declared strings even where validated state uses shorter IDs.
	allocation := body.Policy.StreamAllocations[0]
	allocation.Resource.Kind = "public_url"
	allocation.Resource.Id = strings.Repeat("\x01", 64)
	allocation.RunId = strings.Repeat("\x01", 64)
	allocation.PublisherObserved = false
	allocation.ObservedAt = now.In(time.FixedZone("test", 23*3600+59*60))
	allocation.ValidUntil = allocation.ObservedAt.Add(10 * time.Second)
	raw, err := json.Marshal(allocation)
	if err != nil {
		t.Fatal(err)
	}
	if maximumFixtureAllocation > 3<<10 || len(raw)+1 > 3<<10 {
		t.Fatal("allocation with its required key exceeds the existing 3 KiB allowance")
	}
	t.Logf("largest fixture allocation: %d bytes; declared maximum including comma: %d bytes", maximumFixtureAllocation, len(raw)+1)

	body.AfterRevision = math.MaxInt64 - 256
	body.Policy.VisitorPolicyRevision = math.MaxInt64
	body.SnapshotRequired = false
	body.Revisions = make([]int64, 256)
	for i := range body.Revisions {
		body.Revisions[i] = body.AfterRevision + int64(i) + 1
	}
	raw, err = json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	const accounted = (16 << 10) + 64*(1<<10) + 4096*192 + 2048*(3<<10) + 2048*128
	if accounted != 7_421_952 || accounted > 8<<20 || len(raw) > accounted {
		t.Fatal("valid combined fixture exceeds the existing response accounting")
	}
	t.Logf("valid combined generated policy with keys and 256 events: %d bytes", len(raw))
}
