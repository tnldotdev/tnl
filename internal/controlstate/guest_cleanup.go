package controlstate

import (
	"context"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

// ForgetGuestPrivateState removes rate-limit digests after one hour and guest
// credentials after the trial ends and all of its public URLs are deleted.
func (d *Database) ForgetGuestPrivateState(ctx context.Context, now time.Time) (int, error) {
	if err := d.requireOpen(); err != nil {
		return 0, err
	}
	queries := controlstatedb.New(d.pool)
	issuance, err := queries.ForgetOldGuestIssuanceDigests(ctx, controlstatedb.ForgetOldGuestIssuanceDigestsParams{
		Cutoff: timestamptz(now.Add(-time.Hour)), BatchSize: 100,
	})
	if err != nil {
		return 0, fmt.Errorf("controlstate: forget guest issuance digests: %w", err)
	}
	runDigests, err := queries.ForgetExpiredGuestRunDigests(ctx, controlstatedb.ForgetExpiredGuestRunDigestsParams{
		Now: timestamptz(now), BatchSize: 100,
	})
	if err != nil {
		return int(issuance), fmt.Errorf("controlstate: forget guest publish run digests: %w", err)
	}
	routingHashes, err := queries.ForgetExpiredGuestRoutingHashes(ctx, controlstatedb.ForgetExpiredGuestRoutingHashesParams{
		Now: timestamptz(now), BatchSize: 100,
	})
	if err != nil {
		return int(issuance + runDigests), fmt.Errorf("controlstate: forget guest routing hashes: %w", err)
	}
	credentials, err := queries.ForgetExpiredGuestCredentials(ctx, controlstatedb.ForgetExpiredGuestCredentialsParams{
		Now: timestamptz(now), BatchSize: 100,
	})
	if err != nil {
		return int(issuance + runDigests + routingHashes), fmt.Errorf("controlstate: forget guest credentials: %w", err)
	}
	return int(issuance + runDigests + routingHashes + credentials), nil
}

type GuestTrialStats struct {
	Issued        int64
	Allocated     int64
	Ready         int64
	Expired       int64
	ReadyLimit    int64
	TransferLimit int64
}

// RecentGuestTrialStats returns service-wide counts from committed trial rows.
func (d *Database) RecentGuestTrialStats(ctx context.Context, now time.Time) (GuestTrialStats, error) {
	if err := d.requireOpen(); err != nil {
		return GuestTrialStats{}, err
	}
	row, err := controlstatedb.New(d.pool).RecentGuestTrialStats(ctx, timestamptz(now.Add(-24*time.Hour)))
	if err != nil {
		return GuestTrialStats{}, fmt.Errorf("controlstate: read guest trial stats: %w", err)
	}
	return GuestTrialStats{
		Issued: row.Issued, Allocated: row.Allocated, Ready: row.Ready,
		Expired: row.Expired, ReadyLimit: row.ReadyLimit, TransferLimit: row.TransferLimit,
	}, nil
}
