package state

import (
	"context"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
)

const serviceAuditIPKeyPurpose = "service-audit"

// callers have authorized observations and locked their service parents. audit
// keys never leave control; distributed allowlist/block keys cannot test them.
func (d *Database) insertServiceObservationBatch(ctx context.Context, tx pgx.Tx, events []serviceaudit.Event, now time.Time) (ServiceObservationResult, error) {
	checked := make([]serviceaudit.Event, len(events))
	keys := make(map[string][32]byte)
	for i, event := range events {
		key, found := keys[event.ServiceID]
		if !found {
			value, err := d.ensureServiceIPKey(ctx, controlstatedb.New(tx), event.ServiceID, serviceAuditIPKeyPurpose)
			if err != nil {
				return ServiceObservationResult{}, err
			}
			key = [32]byte(value)
			clear(value)
			keys[event.ServiceID] = key
		}
		source, err := netip.ParseAddr(event.SourceIP)
		if err != nil {
			return ServiceObservationResult{}, serviceaudit.ErrInvalid
		}
		event.SourceDigest, err = ippolicy.HashAddress(key, source)
		if err != nil {
			return ServiceObservationResult{}, err
		}
		event.SourceIP = ""
		checked[i] = event
	}
	return insertServiceAuditBatch(ctx, tx, checked, now)
}
