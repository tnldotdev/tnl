package tnldruntime

import (
	"context"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

type workloadCleanupFixture struct {
	t      *testing.T
	calls  int
	cancel context.CancelFunc
}

func (s *workloadCleanupFixture) CleanupWorkloads(ctx context.Context, _ time.Time, limit int) (int64, error) {
	s.t.Helper()
	deadline, bounded := ctx.Deadline()
	if limit != 1000 || !bounded || time.Until(deadline) > 5*time.Second {
		s.t.Fatal("production cleanup lacks its batch or operation bound")
	}
	s.calls++
	if s.calls == 1 {
		return 9000, nil
	}
	s.cancel()
	<-ctx.Done()
	return 0, ctx.Err()
}

func TestWorkloadCleanupDrainsAndJoins(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	store := &workloadCleanupFixture{t: t, cancel: cancel}
	metrics := observability.New("control")
	if err := runWorkloadCleanup(ctx, store, metrics); err != nil || store.calls != 2 {
		t.Fatalf("cleanup did not drain and join cancellation: calls=%d err=%v", store.calls, err)
	}
	families, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "tnl_control_cleanup_items_total" {
			for _, point := range family.Metric {
				if point.GetCounter().GetValue() == 9000 {
					return
				}
			}
		}
	}
	t.Fatal("workload cleanup progress was not observed")
}
