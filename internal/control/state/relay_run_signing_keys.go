package state

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// superseded bindings outlive the signed native peer pair and leg proof windows.
// the current run has no supersession timestamp, regardless of its age.
const relayRunSigningKeyRetention = 10 * time.Minute

// CleanupRelayRunSigningKeys removes only superseded bindings past the safety
// horizon. registration and cleanup lock leases before key rows so a returning
// run cannot change its key while cleanup races its registration.
func (d *Database) CleanupRelayRunSigningKeys(ctx context.Context, now time.Time, limit int) (int64, error) {
	if now.IsZero() || limit < 1 || limit > 10000 {
		return 0, errors.New("controlstate: relay run key cleanup arguments are invalid")
	}
	if err := d.requireOpen(); err != nil {
		return 0, err
	}
	removed, err := controlstatedb.New(d.pool).CleanupSupersededRelayRunSigningKeys(ctx, controlstatedb.CleanupSupersededRelayRunSigningKeysParams{
		Cutoff: timestamptz(now.Add(-relayRunSigningKeyRetention)), BatchSize: int32(limit),
	})
	if err != nil {
		return 0, fmt.Errorf("controlstate: clean up relay run signing keys: %w", err)
	}
	return removed, nil
}
