package maintenance

import (
	"context"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

type auditCleanupFixture struct {
	calls  int
	cancel context.CancelFunc
}

func (s *auditCleanupFixture) CleanupServiceAudit(_ context.Context, _ time.Time, limit int) (int64, error) {
	if limit != 1000 {
		panic("cleanup is not bounded")
	}
	s.calls++
	if s.calls == 1 {
		return 1000, nil
	}
	s.cancel()
	return 0, nil
}
func TestServiceAuditWorkerDrainsBatchesAndJoinsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	store := &auditCleanupFixture{cancel: cancel}
	metrics := observability.New("control")
	if err := RunServiceAuditCleanup(ctx, store, metrics); err != nil || store.calls != 2 {
		t.Fatalf("cleanup did not drain and join: %d %v", store.calls, err)
	}
	families, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, family := range families {
		if family.GetName() == "tnl_control_cleanup_items_total" {
			for _, point := range family.Metric {
				if point.GetCounter().GetValue() == 1000 {
					seen = true
				}
			}
		}
	}
	if !seen {
		t.Fatal("cleanup worker did not record its committed removal batch")
	}
}
