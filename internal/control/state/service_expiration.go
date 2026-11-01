package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// private runs use the same expiration worker and relay reservation counters
// as HTTP runs. a departed publisher must not hold placement indefinitely.
func (d *Database) ExpireServiceRuns(ctx context.Context, now time.Time) (count int, retErr error) {
	rows, err := d.pool.Query(ctx, `SELECT run.id,run.service_id FROM control.service_runs run
	    JOIN control.services service ON service.id=run.service_id JOIN control.teams team ON team.id=service.team_id
	    JOIN control.publisher_grants grant_record ON grant_record.id=run.publisher_grant_id JOIN control.publisher_identities publisher ON publisher.id=run.publisher_identity_id
	    WHERE run.closed_at IS NULL AND(run.publisher_expires_at<=$1 OR run.state='prepared' AND run.preparation_expires_at<=$1
	        OR NOT service.enabled OR service.deleted_at IS NOT NULL OR team.deleted_at IS NOT NULL OR publisher.revoked_at IS NOT NULL
	        OR grant_record.revoked_at IS NOT NULL OR grant_record.expires_at<=$1)
	    ORDER BY run.publisher_expires_at,run.id LIMIT 100`, now)
	if err != nil {
		return 0, err
	}
	type candidate struct{ id, service string }
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err = rows.Scan(&c.id, &c.service); err != nil {
			rows.Close()
			return 0, err
		}
		candidates = append(candidates, c)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	for _, c := range candidates {
		closed, err := func() (bool, error) {
			tx, err := d.pool.Begin(ctx)
			if err != nil {
				return false, err
			}
			defer tx.Rollback(ctx)
			q := controlstatedb.New(tx)
			service, err := q.LockService(ctx, c.service)
			if errors.Is(err, pgx.ErrNoRows) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: c.id, ServiceID: c.service})
			if err != nil {
				return false, err
			}
			if run.ClosedAt.Valid {
				return false, nil
			}
			var current bool
			if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.teams team JOIN control.publisher_grants g ON g.id=$2
			    JOIN control.publisher_identities p ON p.id=$3 WHERE team.id=$1 AND team.deleted_at IS NULL AND g.revoked_at IS NULL
			    AND(g.expires_at IS NULL OR g.expires_at>$4) AND p.revoked_at IS NULL)`, service.TeamID, run.PublisherGrantID, run.PublisherIdentityID, now).Scan(&current); err != nil {
				return false, err
			}
			if current && service.Enabled && !service.DeletedAt.Valid && run.PublisherExpiresAt.Time.After(now) && (run.State != "prepared" || run.PreparationExpiresAt.Time.After(now)) {
				return false, nil
			}
			if _, err = q.CloseServiceRun(ctx, controlstatedb.CloseServiceRunParams{ID: c.id, ServiceID: c.service, RunNumber: run.RunNumber, Now: timestamptz(now)}); err != nil {
				return false, err
			}
			return true, tx.Commit(ctx)
		}()
		if err != nil {
			return count, err
		}
		if closed {
			count++
		}
	}
	if _, err = d.pool.Exec(ctx, `DELETE FROM control.service_client_certificates WHERE certificate_digest IN(SELECT certificate_digest FROM control.service_client_certificates WHERE expires_at<$1 ORDER BY expires_at LIMIT 1000)`, now.Add(-24*time.Hour)); err != nil {
		return count, err
	}
	if _, err = d.pool.Exec(ctx, `DELETE FROM control.public_service_visitors WHERE visitor_connection_id IN(SELECT visitor_connection_id FROM control.public_service_visitors WHERE valid_until<$1 OR closed_at<$1 ORDER BY valid_until LIMIT 1000)`, now.Add(-24*time.Hour)); err != nil {
		return count, err
	}
	if _, err = d.pool.Exec(ctx, `DELETE FROM control.connector_peer_audit_bindings WHERE pair_id IN
		(SELECT pair_id FROM control.connector_peer_audit_bindings WHERE expires_at<$1 ORDER BY expires_at,pair_id LIMIT 1000)`, now.Add(-24*time.Hour)); err != nil {
		return count, err
	}
	if _, err = d.ReleaseServicePorts(ctx, now); err != nil {
		return count, err
	}
	return count, nil
}
