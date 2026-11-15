package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/httpprotection"
)

const ephemeralServiceGracePeriod = 2 * time.Minute

const serviceRunExpirationBatchSize = 100

// admission cleanup is restricted to actual reservations on the relay services
// selected by placement. recheck current eligibility (as in LockEligibleRelayLeases)
// without acquiring relay locks before the closure's reservation mutation.
const serviceRunReclamationScope = `EXISTS(
	SELECT 1 FROM control.service_connection_slots slot
	JOIN control.relay_services relay ON relay.relay_service_id=slot.relay_service_id AND relay.enabled
	JOIN control.relay_leases lease ON lease.relay_service_id=relay.relay_service_id
	WHERE slot.service_run_id=run.id AND slot.session_open
	  AND slot.state IN('assigned','connected','ready','draining')
	  AND slot.relay_service_id=ANY($2::text[])
	  AND lease.lease_expires_at>$1 AND NOT lease.draining AND lease.protocol_version=1
	  AND lease.connection_capacity>0 AND lease.stream_capacity>0)`

// nil relay services retain ordinary expiry, including lost publisher permission.
// a nonnil placement selection permits only deadline-expired consuming runs.
// both paths share one bounded discovery and the same per-candidate closure owner.
func (d *Database) expireServiceRunCandidates(ctx context.Context, clock authorizationClock, relayServices []string) (count int, retErr error) {
	now := clock.current()
	// rank within each immutable owner before limiting the read-only discovery.
	// one busy owner's first hundred runs must not hide another owner's first.
	rows, err := d.pool.Query(ctx, `SELECT id,service_id,team_id,guest_id FROM (
	    SELECT run.id,run.service_id,service.team_id,service.guest_id,run.publisher_expires_at,
	        row_number() OVER (PARTITION BY service.team_id,service.guest_id ORDER BY run.publisher_expires_at,run.id) AS owner_position
	    FROM control.service_runs run JOIN control.services service ON service.id=run.service_id
	    WHERE run.closed_at IS NULL AND(run.serving_until<=$1 OR run.state='prepared' AND run.preparation_expires_at<=$1
	        OR NOT $3::boolean AND NOT EXISTS(SELECT 1 FROM control.publisher_service_permission(run.publisher_identity_id,run.publisher_grant_id,run.service_id,$1) permission
	            JOIN control.publisher_grants grant_record ON grant_record.id=run.publisher_grant_id
	            JOIN control.publisher_identity_keys signing ON signing.id=run.publisher_key_id AND signing.publisher_identity_id=run.publisher_identity_id
	            WHERE grant_record.kind='service' OR signing.retired_at IS NULL))
	      AND (NOT $3::boolean OR `+serviceRunReclamationScope+`)
	    ) candidates ORDER BY owner_position,publisher_expires_at,id LIMIT $4`, now, relayServices, relayServices != nil, serviceRunExpirationBatchSize)
	if err != nil {
		return 0, err
	}
	type owner struct{ team, guest pgtype.Text }
	type candidate struct {
		id, service string
		owner       owner
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err = rows.Scan(&c.id, &c.service, &c.owner.team, &c.owner.guest); err != nil {
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
	busyOwners := make(map[owner]bool)
	for _, c := range candidates {
		if busyOwners[c.owner] {
			continue
		}
		closed, available, err := func() (_ bool, _ bool, retErr error) {
			tx, err := d.pool.Begin(ctx)
			if err != nil {
				return false, false, err
			}
			defer rollback(ctx, tx, "expire service run", &retErr)()
			q := controlstatedb.New(tx)
			locked, err := tryLockServiceOwner(ctx, tx, c.service)
			if err != nil || !locked {
				return false, false, err
			}
			var id string
			err = tx.QueryRow(ctx, `SELECT id FROM control.services WHERE id=$1 FOR UPDATE SKIP LOCKED`, c.service).Scan(&id)
			if errors.Is(err, pgx.ErrNoRows) {
				return false, false, nil
			}
			if err != nil {
				return false, false, err
			}
			err = tx.QueryRow(ctx, `SELECT id FROM control.service_runs WHERE id=$1 AND service_id=$2 FOR UPDATE SKIP LOCKED`, c.id, c.service).Scan(&id)
			if errors.Is(err, pgx.ErrNoRows) {
				return false, false, nil
			}
			if err != nil {
				return false, false, err
			}
			// the exact row is already held exclusively. reuse the generated
			// scan and current permission owner rather than copying their models.
			run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: c.id, ServiceID: c.service})
			if err != nil {
				return false, false, err
			}
			if run.ClosedAt.Valid {
				return false, true, nil
			}
			if relayServices != nil {
				checkedAt := clock.current()
				if run.ServingUntil.Time.After(checkedAt) && (run.State != "prepared" || run.PreparationExpiresAt.Time.After(checkedAt)) {
					return false, true, nil
				}
				var relevant bool
				if err := tx.QueryRow(ctx, `SELECT `+serviceRunReclamationScope+`
					FROM control.service_runs run WHERE run.id=$3`, checkedAt, relayServices, run.ID).Scan(&relevant); err != nil {
					return false, false, err
				}
				if !relevant {
					return false, true, nil
				}
			}
			if run.GuestID.Valid {
				// permission reuses these locks in trial -> service -> run ->
				// publisher -> grant order, without a later blocking acquisition.
				err = tx.QueryRow(ctx, `SELECT id FROM control.publisher_identities WHERE id=$1 FOR UPDATE SKIP LOCKED`, run.PublisherIdentityID).Scan(&id)
				if errors.Is(err, pgx.ErrNoRows) {
					return false, false, nil
				}
				if err != nil {
					return false, false, err
				}
				err = tx.QueryRow(ctx, `SELECT id FROM control.publisher_grants WHERE id=$1 AND publisher_identity_id=$2 FOR SHARE SKIP LOCKED`, run.PublisherGrantID, run.PublisherIdentityID).Scan(&id)
				if errors.Is(err, pgx.ErrNoRows) {
					return false, false, nil
				}
				if err != nil {
					return false, false, err
				}
			}
			checkedAt := clock.current()
			_, permissionErr := serviceRunPublisherPermission(ctx, tx, run, checkedAt)
			if permissionErr != nil && !failure.Only(permissionErr, ErrServiceAccess) {
				return false, false, permissionErr
			}
			if permissionErr == nil && run.ServingUntil.Time.After(checkedAt) && (run.State != "prepared" || run.PreparationExpiresAt.Time.After(checkedAt)) {
				return false, true, nil
			}
			changed, err := closeServiceRun(ctx, q, run, checkedAt)
			if err != nil {
				return false, false, err
			}
			if err := tx.Commit(ctx); err != nil {
				return false, false, err
			}
			return changed > 0, true, nil
		}()
		if err != nil {
			return count, err
		}
		if !available {
			busyOwners[c.owner] = true
		}
		if closed {
			count++
		}
	}
	return count, nil
}

// every protocol uses the same expiration worker and relay reservation counters.
// a departed publisher must not hold placement indefinitely.
func (d *Database) ExpireServiceRuns(ctx context.Context, now time.Time) (count int, retErr error) {
	clock := newAuthorizationClock(now)
	count, err := d.expireServiceRunCandidates(ctx, clock, nil)
	if err != nil {
		return count, err
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
	if err = controlstatedb.New(d.pool).PruneHTTPTemporaryBlocks(ctx, timestamptz(now.Add(-httpprotection.BlockRetention))); err != nil {
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
