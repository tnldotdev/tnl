-- name: ClaimDNSRouteWork :one
WITH candidate AS (
    SELECT id
    FROM control.routes
    WHERE dns_state IN ('pending', 'removing')
      AND dns_available_at <= sqlc.arg(claimed_at)
      AND (dns_work_owner IS NULL OR dns_work_expires_at <= sqlc.arg(claimed_at))
    ORDER BY dns_available_at, id
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
UPDATE control.routes AS routes
SET dns_work_owner = sqlc.arg(work_owner),
    dns_work_epoch = routes.dns_work_epoch + 1,
    dns_work_expires_at = sqlc.arg(work_expires_at),
    dns_attempts = routes.dns_attempts + 1,
    updated_at = GREATEST(routes.updated_at, sqlc.arg(claimed_at))
FROM candidate
WHERE routes.id = candidate.id
RETURNING routes.*;

-- name: SaveDNSRouteWork :one
UPDATE control.routes
SET dns_state = sqlc.arg(dns_state),
    dns_revision = dns_revision + 1,
    dns_work_owner = NULL,
    dns_work_expires_at = NULL,
    dns_available_at = sqlc.narg(dns_available_at),
    dns_last_error = sqlc.narg(dns_last_error),
    updated_at = sqlc.arg(completed_at)
WHERE id = sqlc.arg(route_id)
  AND dns_work_owner = sqlc.arg(work_owner)
  AND dns_work_epoch = sqlc.arg(work_epoch)
  AND dns_work_expires_at > sqlc.arg(completed_at)
  AND dns_revision = sqlc.arg(expected_dns_revision)
RETURNING *;
