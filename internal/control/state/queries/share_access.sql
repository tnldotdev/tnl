-- name: GetActiveShareForService :one
SELECT share.* FROM control.shares share
JOIN control.share_services included ON included.share_id=share.id
WHERE share.id=sqlc.arg(share_id) AND included.service_id=sqlc.arg(service_id)
    AND share.revoked_at IS NULL AND share.expires_at>sqlc.arg(now)
    AND (share.scope<>'guest' OR control.guest_share_live(share.guest_id,sqlc.arg(now)));

-- name: CountActiveSharesForService :one
SELECT count(*)::bigint FROM control.shares share
JOIN control.share_services included ON included.share_id=share.id
WHERE included.service_id=sqlc.arg(service_id) AND share.revoked_at IS NULL AND share.expires_at>sqlc.arg(now)
    AND (share.scope<>'guest' OR control.guest_share_live(share.guest_id,sqlc.arg(now)));

-- name: CountActiveShareCookiesForService :one
SELECT count(*)::bigint FROM control.share_cookies cookie
JOIN control.shares share ON share.id=cookie.share_id
WHERE cookie.service_id=sqlc.arg(service_id) AND cookie.expires_at>sqlc.arg(now)
    AND share.revoked_at IS NULL AND share.expires_at>sqlc.arg(now)
    AND (share.scope<>'guest' OR control.guest_share_live(share.guest_id,sqlc.arg(now)));

-- name: ListReadyShareServices :many
-- aggregate replica runs before building one redirect per service hostname.
SELECT service.id AS service_id,service.certificate_hostname,
    array_agg(run.id ORDER BY run.run_number)::text[] AS run_ids
FROM control.share_services included
JOIN control.services service ON service.id=included.service_id
JOIN control.service_runs run ON run.service_id=service.id
WHERE included.share_id=sqlc.arg(share_id) AND service.enabled AND service.deleted_at IS NULL
    AND service.protocol='http' AND run.state='ready' AND run.healthy AND run.closed_at IS NULL
    AND run.publisher_expires_at>sqlc.arg(now) AND run.certificate_expires_at>sqlc.arg(now)
    AND EXISTS(SELECT 1 FROM control.publisher_service_permission(run.publisher_identity_id,
        run.publisher_grant_id,service.id,sqlc.arg(now)))
GROUP BY service.id,service.certificate_hostname ORDER BY service.id;

-- name: InsertShareCookie :one
INSERT INTO control.share_cookies(token_digest,share_id,service_id,team_id,run_ids,created_at,expires_at)
SELECT sqlc.arg(token_digest),share.id,included.service_id,share.team_id,sqlc.arg(run_ids)::text[],
    sqlc.arg(created_at),LEAST(share.expires_at,sqlc.arg(expires_at)::timestamptz)
FROM control.shares share
JOIN control.share_services included ON included.share_id=share.id AND included.service_id=sqlc.arg(service_id)
WHERE share.id=sqlc.arg(share_id) AND share.revoked_at IS NULL AND share.expires_at>sqlc.arg(created_at)
    AND (share.scope<>'guest' OR control.guest_share_live(share.guest_id,sqlc.arg(created_at)))
RETURNING token_digest;

-- name: InsertShareHandoff :one
INSERT INTO control.share_handoffs(token_digest,share_id,service_id,team_id,run_ids,redirect_url,bridge,created_at,expires_at)
SELECT sqlc.arg(token_digest),share.id,included.service_id,share.team_id,sqlc.arg(run_ids)::text[],
    sqlc.arg(next_url),sqlc.arg(bridge),sqlc.arg(created_at),sqlc.arg(expires_at)
FROM control.shares share
JOIN control.share_services included ON included.share_id=share.id AND included.service_id=sqlc.arg(service_id)
WHERE share.id=sqlc.arg(share_id) AND share.revoked_at IS NULL AND share.expires_at>sqlc.arg(created_at)
    AND (share.scope<>'guest' OR control.guest_share_live(share.guest_id,sqlc.arg(created_at)))
RETURNING token_digest;

-- name: ConsumeShareHandoff :one
UPDATE control.share_handoffs handoff SET consumed_at=sqlc.arg(now)
FROM control.shares share
WHERE handoff.token_digest=sqlc.arg(token_digest) AND handoff.service_id=sqlc.arg(service_id)
    AND sqlc.arg(service_run_id)::text=ANY(handoff.run_ids)
    AND handoff.consumed_at IS NULL AND handoff.expires_at>sqlc.arg(now)
    AND share.id=handoff.share_id AND share.revoked_at IS NULL AND share.expires_at>sqlc.arg(now)
    AND (share.scope<>'guest' OR control.guest_share_live(share.guest_id,sqlc.arg(now)))
RETURNING handoff.share_id,handoff.redirect_url,handoff.bridge,handoff.run_ids;

-- name: DeleteExpiredShareCookies :exec
DELETE FROM control.share_cookies cookie WHERE cookie.token_digest IN
    (SELECT expired.token_digest FROM control.share_cookies expired WHERE expired.expires_at<=sqlc.arg(now) LIMIT 100);

-- name: DeleteFinishedShareHandoffs :exec
DELETE FROM control.share_handoffs handoff WHERE handoff.token_digest IN
    (SELECT finished.token_digest FROM control.share_handoffs finished WHERE finished.expires_at<=sqlc.arg(now) OR finished.consumed_at IS NOT NULL LIMIT 100);
