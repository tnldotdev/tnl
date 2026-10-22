package maintenance

import (
	"context"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
)

type guestPrivateStateStore interface {
	ForgetGuestPrivateState(context.Context, time.Time) (int, error)
	RecentGuestTrialStats(context.Context, time.Time) (controlstate.GuestTrialStats, error)
}

func RunGuestPrivateStateCleanup(ctx context.Context, store guestPrivateStateStore, metrics *observability.Metrics) error {
	return runBatchCleanup(ctx, 30*time.Second, func(ctx context.Context, now time.Time) (int, error) {
		count, err := store.ForgetGuestPrivateState(ctx, now)
		if err != nil {
			return count, err
		}
		stats, err := store.RecentGuestTrialStats(ctx, now)
		if err == nil {
			metrics.SetGuestTrialStats(stats.Issued, stats.Allocated, stats.Ready,
				stats.Expired, stats.ReadyLimit, stats.TransferLimit)
		}
		return count, err
	}, func(count int, err error) {
		metrics.ObserveCleanup("guest_private_state", count, false, err)
		if err != nil && ctx.Err() == nil {
			operatorlog.ReportContext(ctx, "clean up guest private state", failure.ServerWorkerFailed, "", err)
		}
	})
}
