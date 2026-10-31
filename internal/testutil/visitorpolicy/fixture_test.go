package visitorpolicy

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
)

func TestMaximumPolicyWireBudget(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 123456789, time.UTC)
	body, _ := Maximum(t, now)
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

	body.AfterRevision = math.MaxInt64 - 256
	body.Policy.VisitorPolicyRevision = math.MaxInt64
	body.SnapshotRequired = false
	body.Revisions = make([]int64, 256)
	for i := range body.Revisions {
		body.Revisions[i] = body.AfterRevision + int64(i) + 1
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	const accounted = (16 << 10) + 64*(1<<10) + 4096*192 + 2048*128
	if accounted > 2<<20 || len(raw) > accounted {
		t.Fatal("valid combined fixture exceeds the existing response accounting")
	}
	t.Logf("valid combined generated policy with keys and 256 events: %d bytes", len(raw))
}
