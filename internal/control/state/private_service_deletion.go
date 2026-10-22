package controlstate

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func (d *Database) DeletePrivateService(ctx context.Context, serviceID, actorID string, now time.Time) (retErr error) {
	if !opaqueid.Valid(serviceID, opaqueid.PrivateServicePrefix) {
		return ErrPrivateServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "delete private service", &retErr)()
	var teamID string
	if err = tx.QueryRow(ctx, `SELECT team_id FROM control.private_services WHERE id=$1 AND deleted_at IS NULL`, serviceID).Scan(&teamID); errors.Is(err, pgx.ErrNoRows) {
		return ErrPrivateServiceAccess
	} else if err != nil {
		return err
	}
	if _, err = controlstatedb.New(tx).LockLocalTeamForMutation(ctx, teamID); errors.Is(err, pgx.ErrNoRows) {
		return ErrPrivateServiceAccess
	} else if err != nil {
		return err
	}
	if err = privateServiceManager(ctx, tx, teamID, actorID); err != nil {
		return err
	}
	if err = lockEnabledPrivateService(ctx, tx, serviceID); err != nil {
		return err
	}
	if err = rejectProjectManagedDefinition(ctx, tx, serviceID); err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	if _, err = tx.Exec(ctx, `UPDATE control.private_service_runs SET state='closed', closed_at=$2
		WHERE private_service_id=$1 AND closed_at IS NULL`, serviceID, now); err != nil {
		return err
	}
	if _, err = q.DeletePrivateService(ctx, controlstatedb.DeletePrivateServiceParams{ID: serviceID, TeamID: teamID, Now: timestamptz(now)}); err != nil {
		return err
	}
	if err = privateRoutingTombstone(ctx, q, serviceID, now); err != nil {
		return err
	}
	if err = auditPrivateMutation(ctx, tx, serviceID, actorID, "service.delete", serviceID, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func privateRoutingTombstone(ctx context.Context, q *controlstatedb.Queries, serviceID string, now time.Time) error {
	return privateRunRoutingTombstone(ctx, q, serviceID, "", 0, now)
}

func privateRunRoutingTombstone(ctx context.Context, q *controlstatedb.Queries, serviceID, runID string, number int64, now time.Time) error {
	clock, err := q.LockPrivateServiceRoutingClock(ctx)
	if err != nil {
		return err
	}
	event, err := q.InsertPrivateServiceRoutingEvent(ctx, controlstatedb.InsertPrivateServiceRoutingEventParams{
		PrivateServiceID: serviceID, Kind: "tombstone", Projection: []byte("[]"),
		PrivateRunID: nullableText(runID), RunNumber: pgtype.Int8{Int64: number, Valid: runID != ""},
		ExpiresAt: timestamptz(now.Add(24 * time.Hour)), Now: timestamptz(now),
	})
	if err != nil {
		return err
	}
	if event.Revision <= clock {
		return errors.New("controlstate: private routing clock is ahead of events")
	}
	_, err = q.AdvancePrivateServiceRoutingClock(ctx, controlstatedb.AdvancePrivateServiceRoutingClockParams{Revision: event.Revision, Now: timestamptz(now)})
	return err
}
