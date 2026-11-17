package state

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// closure and shared issuance serialize on the existing order row. retain a live
// work lease: revision fencing prevents its save, but cleanup must not overtake
// an in-flight provider call before the original operation/work deadline.
func retireUnusedServiceCertificateOrders(ctx context.Context, q *controlstatedb.Queries, run string, now time.Time) error {
	clock := newAuthorizationClock(now)
	ids, err := q.LockServiceCertificateOrdersForConsumer(ctx, run)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := q.RetireUnusedServiceCertificateOrder(ctx, controlstatedb.RetireUnusedServiceCertificateOrderParams{
			IssuanceID: id, Now: timestamptz(clock.current()),
		}); err != nil {
			return err
		}
	}
	return nil
}
