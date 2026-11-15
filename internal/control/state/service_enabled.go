package state

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// SetServiceEnabled changes operational availability, not the saved declaration.
// suspension closes runs without releasing endpoints, grants, or project ownership.
// enabling permits new runs and never revives a closed publication.
func (d *Database) SetServiceEnabled(ctx context.Context, serviceID, actorID string, enabled bool, now time.Time) (result ServiceRecord, retErr error) {
	if !opaqueid.Valid(serviceID, opaqueid.ServicePrefix) || now.IsZero() {
		return result, ErrServiceAccess
	}
	clock := newAuthorizationClock(now)
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "change service availability", &retErr)()
	service, err := lockManagedService(ctx, tx, serviceID, actorID)
	if err != nil {
		return result, err
	}
	if enabled && service.ExpiresAt.Valid && !service.ExpiresAt.Time.After(clock.current()) {
		return result, ErrServiceAccess
	}
	q := controlstatedb.New(tx)
	if service.Enabled != enabled {
		if !enabled {
			if err = closeServiceRuns(ctx, tx, serviceID, clock.current()); err != nil {
				return result, err
			}
		}
		service, err = q.SetServiceEnabled(ctx, controlstatedb.SetServiceEnabledParams{
			ID: serviceID, Enabled: enabled, Now: timestamptz(clock.current()),
		})
		if err != nil {
			return result, err
		}
		request, err := opaqueid.New(opaqueid.RequestPrefix)
		if err != nil {
			return result, err
		}
		if err = auditPrivateMutation(ctx, tx, serviceID, actorID, "service.update", request, clock.current()); err != nil {
			return result, err
		}
	}
	result, err = checkedServiceRecord(service)
	if err != nil {
		return result, err
	}
	if err = serviceSource(ctx, q, &result); err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ServiceRecord{}, err
	}
	return result, nil
}
