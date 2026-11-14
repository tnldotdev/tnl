package state

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func (d *Database) DeleteService(ctx context.Context, serviceID, actorID string, now time.Time) (retErr error) {
	if !opaqueid.Valid(serviceID, opaqueid.ServicePrefix) {
		return ErrServiceAccess
	}
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "delete service", &retErr)()
	service, err := lockService(ctx, tx, serviceID, actorID)
	if err != nil {
		return err
	}
	if err = rejectProjectManagedDefinition(ctx, tx, serviceID); err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	if _, err = tx.Exec(ctx, `UPDATE control.service_runs SET state='closed', closed_at=$2
		WHERE service_id=$1 AND closed_at IS NULL`, serviceID, now); err != nil {
		return err
	}
	if _, err = q.DeleteService(ctx, controlstatedb.DeleteServiceParams{ID: serviceID, TeamID: service.TeamID, Now: timestamptz(now)}); err != nil {
		return err
	}
	if err = auditPrivateMutation(ctx, tx, serviceID, actorID, "service.delete", serviceID, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
