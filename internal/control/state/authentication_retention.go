package state

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// CleanupAuthentication removes expired credentials outside authentication
// transactions. each query commits its own bounded batch.
func (d *Database) CleanupAuthentication(ctx context.Context, now time.Time, limit int) (int64, error) {
	if now.IsZero() || limit < 1 || limit > 10000 {
		return 0, ErrAuthorityInvalid
	}
	q := controlstatedb.New(d.pool)
	var removed int64
	count, err := q.CleanupPublisherAssertions(ctx, controlstatedb.CleanupPublisherAssertionsParams{Now: timestamptz(now), BatchSize: int32(limit)})
	removed += count
	if err != nil {
		return removed, err
	}
	count, err = q.CleanupPublisherAccess(ctx, controlstatedb.CleanupPublisherAccessParams{Now: timestamptz(now), BatchSize: int32(limit)})
	removed += count
	if err != nil {
		return removed, err
	}
	count, err = q.CleanupCompanyLoginIntents(ctx, controlstatedb.CleanupCompanyLoginIntentsParams{Now: timestamptz(now), BatchSize: int32(limit)})
	removed += count
	if err != nil {
		return removed, err
	}
	count, err = q.CleanupOIDCAssertions(ctx, controlstatedb.CleanupOIDCAssertionsParams{Now: timestamptz(now), BatchSize: int32(limit)})
	return removed + count, err
}
