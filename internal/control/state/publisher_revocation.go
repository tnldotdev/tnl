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
// URL/run when they recheck it. closures may then take audit and routing clocks
// without waiting for another service parent. unrelated services stay unlocked.
func lockPublisherPublications(ctx context.Context, tx pgx.Tx, team, publisher, grant string) error {
	if _, err := tx.Exec(ctx, `SELECT service.id FROM control.services service
		WHERE service.team_id=$1 AND service.id IN (
			SELECT service_id FROM control.publisher_grants
			WHERE publisher_identity_id=$2 AND ($3='' OR id=$3) AND kind='service')
		ORDER BY service.id FOR UPDATE OF service`, team, publisher, grant); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT service.id FROM control.public_urls service
		WHERE service.team_id=$1 AND service.id IN (
			SELECT run.public_url_id FROM control.publish_runs run
			JOIN control.publish_run_publisher_grants binding ON binding.publish_run_id=run.id
			WHERE binding.publisher_identity_id=$2 AND ($3='' OR binding.publisher_grant_id=$3) AND run.closed_at IS NULL)
		ORDER BY service.id FOR NO KEY UPDATE OF service`, team, publisher, grant)
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
	if _, err = q.CloseServiceRun(ctx, controlstatedb.CloseServiceRunParams{
		ID: runID, ServiceID: serviceID, RunNumber: number, Now: timestamptz(now),
	}); err != nil {
		return err
	}
	return nil
}

func closeRevokedPublicPublications(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, publisherIdentityID, grantID string, now time.Time) error {
	rows, err := tx.Query(ctx, `SELECT DISTINCT run.public_url_id FROM control.publish_runs run JOIN control.publish_run_publisher_grants publisher ON publisher.publish_run_id=run.id
	    WHERE publisher.publisher_identity_id=$1 AND ($2='' OR publisher.publisher_grant_id=$2) AND run.closed_at IS NULL ORDER BY run.public_url_id`, publisherIdentityID, grantID)
	if err != nil {
		return err
	}
	var services []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		services = append(services, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	pending := pendingIngressRoutingTableEvents{}
	for _, id := range services {
		service, err := q.LockPublicURLForRun(ctx, id)
		if err != nil {
			return err
		}
		runs, err := q.ListOpenPublishRuns(ctx, id)
		if err != nil {
			return err
		}
		for _, run := range runs {
			binding, err := q.GetPublisherRun(ctx, run.ID)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			if binding.PublisherIdentityID != publisherIdentityID || grantID != "" && binding.PublisherGrantID != grantID {
				continue
			}
			if err = closePublishRun(ctx, q, &pending, service, run, PublishRunClosed, now, "publisher_revoked"); err != nil {
				return err
			}
		}
	}
	return pending.publish(ctx, q)
}
