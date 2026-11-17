package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// service deletion conditions describe the manager's observed settings, not
// publisher, guest, run-token, or authoritative project cleanup permission.
type ServiceDeleteConditions struct {
	Revision      int64
	Unconditional bool
}

func (c ServiceDeleteConditions) Validate() error {
	if c.Revision < 0 || (c.Revision > 0) == c.Unconditional {
		return ErrProjectConfigurationInvalid
	}
	return nil
}

func (d *Database) DeleteService(ctx context.Context, serviceID, actorID string, conditions ServiceDeleteConditions, now time.Time) error {
	if err := conditions.Validate(); err != nil {
		return err
	}
	return d.deleteService(ctx, serviceID, actorID, conditions, nil, now)
}

// guest cleanup uses exact credential/source authority independently of ordinary
// management conditions, including terminal retries after READY exhaustion.
func (d *Database) DeleteGuestService(ctx context.Context, serviceID string, credential GuestCredential, now time.Time) error {
	return d.deleteService(ctx, serviceID, "", ServiceDeleteConditions{}, &credential, now)
}

func (d *Database) deleteService(ctx context.Context, serviceID, actorID string, conditions ServiceDeleteConditions, credential *GuestCredential, now time.Time) (retErr error) {
	clock := newAuthorizationClock(now)
	if !opaqueid.Valid(serviceID, opaqueid.ServicePrefix) {
		return ErrServiceAccess
	}
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "delete service", &retErr)()
	q := controlstatedb.New(tx)
	var service controlstatedb.ControlService
	if credential != nil {
		trial, authErr := d.lockGuestCredential(ctx, q, *credential, clock)
		if authErr != nil {
			return authErr
		}
		service, err = q.LockService(ctx, serviceID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrServiceAccess
		}
		if err == nil && (service.GuestID.String != trial.ID || service.TeamID.Valid) {
			return ErrServiceAccess
		}
		if err == nil && service.DeletedAt.Valid {
			return tx.Commit(ctx)
		}
	} else {
		service, err = lockManagedService(ctx, tx, serviceID, actorID)
	}
	if err != nil {
		return err
	}
	if err = rejectProjectManagedDefinition(ctx, tx, serviceID); err != nil {
		return err
	}
	// compare only the current authorized, locked row, before any closure,
	// tombstone, audit, policy change, or endpoint retirement can be written.
	if credential == nil && !conditions.Unconditional && conditions.Revision != service.ServiceRevision {
		return ErrServiceConflict
	}
	if err = closeServiceRuns(ctx, tx, serviceID, clock.current()); err != nil {
		return err
	}
	if _, err = q.DeleteService(ctx, controlstatedb.DeleteServiceParams{ID: serviceID, TeamID: service.TeamID, GuestID: service.GuestID, Now: timestamptz(clock.current())}); err != nil {
		return err
	}
	if err = auditPrivateMutation(ctx, tx, serviceID, actorID, "service.delete", serviceID, now); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		return err
	}
	// cleanup ignores READY exhaustion, but never extends the absolute trial.
	if service.GuestID.Valid && !service.ExpiresAt.Time.After(clock.current()) {
		return ErrGuestTrialSpent
	}
	return tx.Commit(ctx)
}
