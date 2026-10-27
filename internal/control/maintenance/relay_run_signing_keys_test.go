package maintenance

import (
	"context"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

type relayRunKeyCleanupFixture struct {
	t      *testing.T
	cancel context.CancelFunc
	calls  int
}

func (s *relayRunKeyCleanupFixture) CleanupRelayRunSigningKeys(ctx context.Context, now time.Time, limit int) (int64, error) {
	s.t.Helper()
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) > 5*time.Second || limit != 1000 || now.IsZero() {
		s.t.Fatal("relay run key cleanup lacked its operation or batch bound")
	}
	s.calls++
	if s.calls == 1 {
		return 1000, nil
	}
	s.cancel()
	return 0, nil
}

func TestRelayRunSigningKeyCleanupDrainsAndObservesBatches(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	store := &relayRunKeyCleanupFixture{t: t, cancel: cancel}
	metrics := observability.New("control")
	if err := RunRelayRunSigningKeyCleanup(ctx, store, metrics); err != nil || store.calls != 2 {
		t.Fatalf("cleanup did not drain bounded batches: calls=%d err=%v", store.calls, err)
	}
	families, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "tnl_control_cleanup_items_total" {
			continue
		}
		for _, point := range family.Metric {
			for _, label := range point.Label {
				if label.GetName() == "tnl_cleanup_kind" && label.GetValue() == "relay_run_signing_keys" && point.GetCounter().GetValue() == 1000 {
					return
				}
			}
		}
	}
	t.Fatal("relay run key cleanup did not report its bounded removal")
}
