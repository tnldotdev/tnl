package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

type guestServiceCredentialKey struct{}

// WithGuestServiceCredential permits only the guest branch of DeleteService.
// generic service management never consumes it or treats a trial as a person.
func WithGuestServiceCredential(ctx context.Context, credential GuestCredential) context.Context {
	return context.WithValue(ctx, guestServiceCredentialKey{}, credential)
}

func (d *Database) DeleteService(ctx context.Context, serviceID, actorID string, now time.Time) (retErr error) {
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
	if credential, guest := ctx.Value(guestServiceCredentialKey{}).(GuestCredential); guest {
		if actorID != "" {
			return ErrServiceAccess
		}
		trial, authErr := d.lockGuestCredential(ctx, q, credential, clock)
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
