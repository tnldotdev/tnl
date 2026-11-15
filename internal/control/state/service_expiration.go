package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

const ephemeralServiceGracePeriod = 2 * time.Minute

// every protocol uses the same expiration worker and relay reservation counters.
// a departed publisher must not hold placement indefinitely.
func (d *Database) ExpireServiceRuns(ctx context.Context, now time.Time) (count int, retErr error) {
	clock := newAuthorizationClock(now)
	rows, err := d.pool.Query(ctx, `SELECT run.id,run.service_id FROM control.service_runs run
	    WHERE run.closed_at IS NULL AND(run.publisher_expires_at<=$1 OR run.state='prepared' AND run.preparation_expires_at<=$1
	        OR NOT EXISTS(SELECT 1 FROM control.publisher_service_permission(run.publisher_identity_id,run.publisher_grant_id,run.service_id,$1) permission
	            JOIN control.publisher_grants grant_record ON grant_record.id=run.publisher_grant_id
	            JOIN control.publisher_identity_keys signing ON signing.id=run.publisher_key_id AND signing.publisher_identity_id=run.publisher_identity_id
	            WHERE grant_record.kind='service' OR signing.retired_at IS NULL))
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
		closed, err := func() (_ bool, retErr error) {
			tx, err := d.pool.Begin(ctx)
			if err != nil {
				return false, err
			}
			defer rollback(ctx, tx, "expire service run", &retErr)()
			q := controlstatedb.New(tx)
			if err = lockServiceOwner(ctx, tx, c.service); errors.Is(err, ErrServiceAccess) {
				return false, nil
			} else if err != nil {
				return false, err
			}
			_, err = q.LockService(ctx, c.service)
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
			checkedAt := clock.current()
			_, permissionErr := serviceRunPublisherPermission(ctx, tx, run, checkedAt)
			if permissionErr != nil && !errors.Is(permissionErr, ErrServiceAccess) {
				return false, permissionErr
			}
			if permissionErr == nil && run.PublisherExpiresAt.Time.After(checkedAt) && (run.State != "prepared" || run.PreparationExpiresAt.Time.After(checkedAt)) {
				return false, nil
			}
			if _, err = closeServiceRun(ctx, q, run, checkedAt); err != nil {
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
	q := controlstatedb.New(d.pool)
	if err = q.DeleteExpiredShareCookies(ctx, timestamptz(now)); err != nil {
		return count, err
	}
	if err = q.DeleteFinishedShareHandoffs(ctx, timestamptz(now)); err != nil {
		return count, err
	}
	if _, err = d.pool.Exec(ctx, `DELETE FROM control.service_client_certificates WHERE certificate_digest IN(SELECT certificate_digest FROM control.service_client_certificates WHERE expires_at<$1 ORDER BY expires_at LIMIT 1000)`, now.Add(-24*time.Hour)); err != nil {
		return count, err
	}
	if _, err = d.pool.Exec(ctx, `DELETE FROM control.public_service_visitors WHERE visitor_connection_id IN(SELECT visitor_connection_id FROM control.public_service_visitors WHERE valid_until<$1 OR closed_at<$1 ORDER BY valid_until LIMIT 1000)`, now.Add(-24*time.Hour)); err != nil {
		return count, err
	}
	if _, err = d.pool.Exec(ctx, `DELETE FROM control.connector_peer_audit_bindings WHERE ctid IN
		(SELECT ctid FROM control.connector_peer_audit_bindings WHERE expires_at<$1 ORDER BY expires_at,pair_id,delivery_generation LIMIT 1000)`, now.Add(-24*time.Hour)); err != nil {
		return count, err
	}
	if _, err = d.ReleaseServicePorts(ctx, now); err != nil {
		return count, err
	}
	expiredServices, err := d.expireServices(ctx, clock.current())
	count += expiredServices
	if err != nil {
		return count, err
	}
	if err = d.expireCompanyEligibility(ctx, clock.current()); err != nil {
		return count, err
	}
	return count, nil
}

// a fixed expiration never renews. ephemeral cleanup instead waits for the last
// run to close and a short idle grace period; endpoint edits cannot extend it.
func (d *Database) expireServices(ctx context.Context, now time.Time) (count int, retErr error) {
	clock := newAuthorizationClock(now)
	rows, err := d.pool.Query(ctx, `SELECT service.id FROM control.services service
	    WHERE service.deleted_at IS NULL
	      AND NOT EXISTS(SELECT 1 FROM control.service_runs run WHERE run.service_id=service.id AND run.closed_at IS NULL)
	      AND (service.expires_at<=$1 OR service.ephemeral
	        AND COALESCE((SELECT max(run.closed_at) FROM control.service_runs run WHERE run.service_id=service.id),service.created_at)<=$2)
	    ORDER BY service.created_at,service.id LIMIT 100`, now, now.Add(-ephemeralServiceGracePeriod))
	if err != nil {
		return 0, err
	}
	type candidate struct{ id string }
	var candidates []candidate
	for rows.Next() {
		var service candidate
		if err := rows.Scan(&service.id); err != nil {
			rows.Close()
			return 0, err
		}
		candidates = append(candidates, service)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	for _, candidate := range candidates {
		deleted, err := func() (_ bool, retErr error) {
			tx, err := d.pool.Begin(ctx)
			if err != nil {
				return false, err
			}
			defer rollback(ctx, tx, "expire service", &retErr)()
			q := controlstatedb.New(tx)
			if err := lockServiceOwner(ctx, tx, candidate.id); errors.Is(err, ErrServiceAccess) {
				return false, nil
			} else if err != nil {
				return false, err
			}
			service, err := q.LockService(ctx, candidate.id)
			if err != nil {
				return false, err
			}
			if service.DeletedAt.Valid {
				return false, nil
			}
			var open bool
			var idleSince time.Time
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.service_runs WHERE service_id=$1 AND closed_at IS NULL),
			    COALESCE((SELECT max(closed_at) FROM control.service_runs WHERE service_id=$1),$2::timestamptz)`,
				service.ID, service.CreatedAt.Time).Scan(&open, &idleSince); err != nil {
				return false, err
			}
			expired := service.ExpiresAt.Valid && !service.ExpiresAt.Time.After(clock.current())
			idle := service.Ephemeral && !idleSince.Add(ephemeralServiceGracePeriod).After(clock.current())
			if open || !expired && !idle {
				return false, nil
			}
			if _, err := q.DeleteService(ctx, controlstatedb.DeleteServiceParams{ID: service.ID, TeamID: service.TeamID, GuestID: service.GuestID, Now: timestamptz(clock.current())}); err != nil {
				return false, err
			}
			if err := auditPrivateMutation(ctx, tx, service.ID, "", "service.delete", "expiration/"+service.ID, now); err != nil {
				return false, err
			}
			if err := tx.Commit(ctx); err != nil {
				return false, err
			}
			return true, nil
		}()
		if err != nil {
			return count, err
		}
		if deleted {
			count++
		}
	}
	return count, nil
}
