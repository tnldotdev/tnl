package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// the team mutation guard fences new grants and runs while this set is read.
// lock every affected parent before the publisher: heartbeats already own their
// service/run when they recheck it. closures may then take audit records
// without waiting for another service parent. unrelated services stay unlocked.
func lockPublisherPublications(ctx context.Context, tx pgx.Tx, team, publisher, grant string) error {
	_, err := tx.Exec(ctx, `SELECT service.id FROM control.services service
		WHERE service.team_id=$1 AND service.id IN (
			SELECT service_id FROM control.service_runs
			WHERE publisher_identity_id=$2 AND ($3='' OR publisher_grant_id=$3) AND closed_at IS NULL)
		ORDER BY service.id FOR UPDATE OF service`, team, publisher, grant)
	return err
}

func closeRevokedPrivatePublication(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, serviceID, publisherIdentityID, grantID string, now time.Time) error {
	if !opaqueid.Valid(serviceID, opaqueid.ServicePrefix) {
		return ErrPublisherIdentity
	}
	service, err := q.LockService(ctx, serviceID)
	if err != nil {
		return err
	}
	if service.DeletedAt.Valid {
		return nil
	}
	var runID string
	var number int64
	err = tx.QueryRow(ctx, `SELECT id, run_number FROM control.service_runs
		WHERE service_id=$1 AND publisher_identity_id=$2 AND ($3='' OR publisher_grant_id=$3)
		AND closed_at IS NULL FOR UPDATE`, serviceID, publisherIdentityID, grantID).Scan(&runID, &number)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: runID, ServiceID: serviceID})
	if err != nil || run.RunNumber != number {
		return errors.Join(ErrServiceAccess, err)
	}
	if _, err = closeServiceRun(ctx, q, run, now); err != nil {
		return err
	}
	return nil
}

// the stored run owns the service binding even when its grant covers several
// services. revoking that grant closes only runs using that exact grant.
func closePublisherServiceRuns(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, publisher, grant string, now time.Time) error {
	rows, err := tx.Query(ctx, `SELECT DISTINCT service_id FROM control.service_runs
		WHERE publisher_identity_id=$1 AND ($2='' OR publisher_grant_id=$2) AND closed_at IS NULL ORDER BY service_id`, publisher, grant)
	if err != nil {
		return err
	}
	services, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, id := range services {
		if err := closeRevokedPrivatePublication(ctx, tx, q, id, publisher, grant, now); err != nil {
			return err
		}
	}
	return nil
}

// callers hold the team mutation guard. close runs bound to the member's
// publisher identity or namespace grant before returning the policy mutation.
func closeMembershipServiceRuns(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, team, member string, now time.Time) error {
	rows, err := tx.Query(ctx, `SELECT run.service_id,run.id FROM control.service_runs run
		JOIN control.services service ON service.id=run.service_id
		JOIN control.publisher_identities publisher ON publisher.id=run.publisher_identity_id
		JOIN control.publisher_grants grant_record ON grant_record.id=run.publisher_grant_id
		WHERE service.team_id=$1 AND run.closed_at IS NULL
		  AND (publisher.owner_membership_id=$2 OR grant_record.membership_id=$2)
		ORDER BY run.service_id,run.id`, team, member)
	if err != nil {
		return err
	}
	type affectedRun struct{ service, run string }
	var runs []affectedRun
	for rows.Next() {
		var candidate affectedRun
		if err = rows.Scan(&candidate.service, &candidate.run); err != nil {
			rows.Close()
			return err
		}
		runs = append(runs, candidate)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, candidate := range runs {
		if _, err = q.LockService(ctx, candidate.service); err != nil {
			return err
		}
		run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: candidate.run, ServiceID: candidate.service})
		if err != nil {
			return err
		}
		if run.ClosedAt.Valid {
			continue
		}
		if _, err = closeServiceRun(ctx, q, run, now); err != nil {
			return err
		}
	}
	return nil
}
