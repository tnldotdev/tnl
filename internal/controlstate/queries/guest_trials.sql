-- name: InsertGuestTrial :one
INSERT INTO control.guest_trials (
    id, credential_id, credential_hash, namespace_label, team_id,
    membership_id, domain_id, dns_authority_reference, source_ip, created_at, updated_at
) VALUES (
    sqlc.arg(id), sqlc.arg(credential_id), sqlc.arg(credential_hash),
    sqlc.arg(namespace_label), sqlc.arg(team_id), sqlc.arg(membership_id),
    sqlc.arg(domain_id), sqlc.arg(dns_authority_reference), sqlc.arg(source_ip), sqlc.arg(created_at), sqlc.arg(created_at)
)
RETURNING *;

-- name: GetGuestTrialByCredentialID :one
SELECT * FROM control.guest_trials
WHERE credential_id = sqlc.arg(credential_id);

-- name: GetGuestTrialByID :one
SELECT * FROM control.guest_trials
WHERE id = sqlc.arg(id);

-- name: LockGuestTrialByID :one
SELECT * FROM control.guest_trials WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: CountGuestCurrentPublicURLs :one
SELECT count(*) FROM control.guest_public_urls AS guest_route
JOIN control.public_urls AS route ON route.id = guest_route.public_url_id
WHERE guest_route.guest_id = sqlc.arg(guest_id)
  AND route.lifecycle_state <> 'deleted';

-- name: CountRecentGuestTrialsByIP :one
SELECT count(*) FROM control.guest_trials
WHERE source_ip = sqlc.arg(source_ip)
  AND created_at >= sqlc.arg(since);

-- name: MarkGuestTrialClaimed :execrows
UPDATE control.guest_trials
SET claimed_at = sqlc.arg(claimed_at), updated_at = sqlc.arg(claimed_at)
WHERE id = sqlc.arg(id)
  AND claimed_at IS NULL;

-- name: InsertGuestPublicURL :exec
INSERT INTO control.guest_public_urls (public_url_id, guest_id, created_at)
VALUES (sqlc.arg(public_url_id), sqlc.arg(guest_id), sqlc.arg(created_at));

-- name: GuestOwnsPublicURL :one
SELECT EXISTS(
    SELECT 1 FROM control.guest_public_urls
    WHERE public_url_id = sqlc.arg(public_url_id)
      AND guest_id = sqlc.arg(guest_id)
);

-- name: GuestForPublicURL :one
SELECT guest_id FROM control.guest_public_urls
WHERE public_url_id = sqlc.arg(public_url_id);

-- name: BeginGuestPublishRun :execrows
UPDATE control.guest_trials AS guest
SET active_publish_run_id = sqlc.arg(publish_run_id), updated_at = sqlc.arg(started_at)
WHERE guest.id = (
    SELECT guest_id FROM control.guest_public_urls
    WHERE public_url_id = sqlc.arg(public_url_id)
)
  AND guest.claimed_at IS NULL
  AND guest.active_publish_run_id IS NULL
  AND guest.used_ready_ns < 900000000000
  AND guest.used_bytes < 5242880;

-- name: MarkGuestRunReady :execrows
UPDATE control.guest_trials
SET active_ready_at = sqlc.arg(ready_at), updated_at = sqlc.arg(ready_at)
WHERE active_publish_run_id = sqlc.arg(publish_run_id)
  AND active_ready_at IS NULL;

-- name: FinishGuestPublishRun :execrows
UPDATE control.guest_trials
SET used_ready_ns = used_ready_ns + CASE
        WHEN active_ready_at IS NULL THEN 0
        ELSE GREATEST(0, (EXTRACT(EPOCH FROM (sqlc.arg(closed_at)::timestamptz - active_ready_at)) * 1000000000)::bigint)
    END,
    active_ready_at = NULL,
    active_publish_run_id = NULL,
    updated_at = sqlc.arg(closed_at)
WHERE active_publish_run_id = sqlc.arg(publish_run_id);

-- name: UpdateGuestTransferredBytes :execrows
UPDATE control.guest_trials AS guest
SET used_bytes = GREATEST(guest.used_bytes, (
        SELECT COALESCE(SUM(buckets.ingress_bytes + buckets.egress_bytes), 0)::bigint
        FROM control.public_url_usage_buckets AS buckets
        JOIN control.guest_public_urls AS routes ON routes.public_url_id = buckets.public_url_id
        WHERE routes.guest_id = guest.id
    )),
    updated_at = GREATEST(guest.updated_at, sqlc.arg(observed_at))
WHERE guest.id = (
    SELECT route.guest_id FROM control.guest_public_urls AS route
    WHERE route.public_url_id = sqlc.arg(guest_route_id)
);

-- name: GuestRunAllowanceSpent :one
SELECT used_bytes >= 5242880
    OR claimed_at IS NOT NULL
    OR used_ready_ns + CASE WHEN active_ready_at IS NULL THEN 0
        ELSE GREATEST(0, (EXTRACT(EPOCH FROM (sqlc.arg(now)::timestamptz - active_ready_at)) * 1000000000)::bigint)
    END >= 900000000000 AS spent
FROM control.guest_trials
WHERE active_publish_run_id = sqlc.arg(publish_run_id);

-- name: LockGuestForVisitor :one
SELECT guest.* FROM control.guest_trials AS guest
JOIN control.guest_public_urls AS routes ON routes.guest_id = guest.id
WHERE routes.public_url_id = sqlc.arg(public_url_id)
FOR UPDATE OF guest;

-- name: GetGuestVisitorSlot :one
SELECT guest_id, ingress_id, expires_at FROM control.guest_visitor_slots
WHERE visitor_connection_id = sqlc.arg(visitor_connection_id);

-- name: CountActiveGuestVisitorSlots :one
SELECT count(*) FROM control.guest_visitor_slots
WHERE guest_id = sqlc.arg(guest_id) AND expires_at > sqlc.arg(now);

-- name: DeleteExpiredGuestVisitorSlots :exec
DELETE FROM control.guest_visitor_slots WHERE expires_at <= sqlc.arg(now);

-- name: UpsertGuestVisitorSlot :execrows
INSERT INTO control.guest_visitor_slots (
    visitor_connection_id, guest_id, ingress_id, expires_at
) VALUES (
    sqlc.arg(visitor_connection_id), sqlc.arg(guest_id), sqlc.arg(ingress_id), sqlc.arg(expires_at)
)
ON CONFLICT (visitor_connection_id) DO UPDATE SET expires_at = EXCLUDED.expires_at
WHERE control.guest_visitor_slots.guest_id = EXCLUDED.guest_id
  AND control.guest_visitor_slots.ingress_id = EXCLUDED.ingress_id;

-- name: ReleaseGuestVisitorSlot :execrows
DELETE FROM control.guest_visitor_slots
WHERE visitor_connection_id = sqlc.arg(visitor_connection_id)
  AND ingress_id = sqlc.arg(ingress_id);
