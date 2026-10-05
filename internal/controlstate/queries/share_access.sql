-- name: EnablePublishRunShareAccess :one
UPDATE control.publish_runs AS run
SET share_capable = true
WHERE run.id = sqlc.arg(publish_run_id)
  AND run.public_url_id = sqlc.arg(public_url_id)
  AND run.publish_run_number = sqlc.arg(publish_run_number)
  AND run.state = 'starting'
  AND EXISTS (
      SELECT 1 FROM control.preview_public_urls AS membership
      JOIN control.previews AS preview ON preview.id = membership.preview_id
      WHERE membership.preview_id = sqlc.arg(preview_id)
        AND membership.public_url_id = run.public_url_id
        AND preview.created_by_identity_id = run.acting_identity_id
  )
RETURNING run.id;

-- name: GetActiveShareForPublicURL :one
SELECT share.id, share.secret_fingerprint, share.expires_at
FROM control.shares AS share
JOIN control.share_public_urls AS included ON included.share_id = share.id
WHERE share.id = sqlc.arg(share_id)
  AND included.public_url_id = sqlc.arg(public_url_id)
  AND share.revoked_at IS NULL
  AND share.expires_at > sqlc.arg(now);

-- name: ListActiveSharesForPublicURL :many
SELECT share.id, share.secret_fingerprint, share.expires_at
FROM control.shares AS share
JOIN control.share_public_urls AS included ON included.share_id = share.id
WHERE included.public_url_id = sqlc.arg(public_url_id)
  AND share.revoked_at IS NULL
  AND share.expires_at > sqlc.arg(now)
ORDER BY share.id LIMIT 256;

-- name: CountActiveSharesForPublicURL :one
SELECT count(*)::bigint FROM control.shares AS share
JOIN control.share_public_urls AS included ON included.share_id = share.id
WHERE included.public_url_id = sqlc.arg(public_url_id)
  AND share.revoked_at IS NULL AND share.expires_at > sqlc.arg(now);

-- name: ListActiveShareCookiesForPublicURL :many
SELECT cookie.share_id, cookie.token_digest, cookie.expires_at
FROM control.share_cookies AS cookie
JOIN control.shares AS share ON share.id = cookie.share_id
WHERE cookie.public_url_id = sqlc.arg(public_url_id)
  AND cookie.expires_at > sqlc.arg(now)
  AND share.revoked_at IS NULL
  AND share.expires_at > sqlc.arg(now)
ORDER BY cookie.created_at DESC LIMIT 2048;

-- name: CountActiveShareCookiesForPublicURL :one
SELECT count(*)::bigint FROM control.share_cookies AS cookie
JOIN control.shares AS share ON share.id = cookie.share_id
WHERE cookie.public_url_id = sqlc.arg(public_url_id)
  AND cookie.expires_at > sqlc.arg(now)
  AND share.revoked_at IS NULL AND share.expires_at > sqlc.arg(now);

-- name: ListReadyShareHostnames :many
SELECT url.id AS public_url_id, url.canonical_hostname
FROM control.share_public_urls AS included
JOIN control.public_urls AS url ON url.id = included.public_url_id
JOIN control.publish_runs AS run ON run.public_url_id = url.id
WHERE included.share_id = sqlc.arg(share_id)
  AND url.lifecycle_state = 'enabled'
  AND run.state = 'ready'
  AND run.publisher_expires_at > sqlc.arg(now)
  AND run.share_capable = true
ORDER BY url.id;

-- name: InsertShareCookie :one
INSERT INTO control.share_cookies (token_digest, share_id, public_url_id, team_id, created_at, expires_at)
SELECT sqlc.arg(token_digest), share.id, sqlc.arg(public_url_id), share.team_id,
       sqlc.arg(created_at), share.expires_at
FROM control.shares AS share
JOIN control.share_public_urls AS included
  ON included.share_id = share.id AND included.public_url_id = sqlc.arg(public_url_id)
WHERE share.id = sqlc.arg(share_id)
  AND share.revoked_at IS NULL
  AND share.expires_at > sqlc.arg(created_at)
RETURNING token_digest;

-- name: InsertShareHandoff :one
INSERT INTO control.share_handoffs (token_digest, share_id, public_url_id, team_id, next_url, bridge, created_at, expires_at)
SELECT sqlc.arg(token_digest), share.id, sqlc.arg(public_url_id), share.team_id,
       sqlc.arg(next_url), sqlc.arg(bridge), sqlc.arg(created_at), sqlc.arg(expires_at)
FROM control.shares AS share
JOIN control.share_public_urls AS included
  ON included.share_id = share.id AND included.public_url_id = sqlc.arg(public_url_id)
WHERE share.id = sqlc.arg(share_id)
  AND share.revoked_at IS NULL
  AND share.expires_at > sqlc.arg(created_at)
RETURNING token_digest;

-- name: ConsumeShareHandoff :one
UPDATE control.share_handoffs AS handoff
SET consumed_at = sqlc.arg(now)
FROM control.shares AS share
WHERE handoff.token_digest = sqlc.arg(token_digest)
  AND handoff.public_url_id = sqlc.arg(public_url_id)
  AND handoff.consumed_at IS NULL
  AND handoff.expires_at > sqlc.arg(now)
  AND share.id = handoff.share_id
  AND share.revoked_at IS NULL
  AND share.expires_at > sqlc.arg(now)
RETURNING handoff.share_id, handoff.next_url, handoff.bridge;

-- name: GetShareCapablePublishRun :one
SELECT run.id
FROM control.publish_runs AS run
WHERE run.id = sqlc.arg(publish_run_id)
  AND run.public_url_id = sqlc.arg(public_url_id)
  AND run.publish_run_number = sqlc.arg(publish_run_number)
  AND run.share_capable = true
  AND run.state IN ('starting', 'ready')
  AND run.publisher_expires_at > sqlc.arg(now);

-- name: DeleteExpiredShareCookies :exec
WITH expired AS (
    SELECT candidate.token_digest FROM control.share_cookies AS candidate
    WHERE candidate.expires_at <= sqlc.arg(now)
    LIMIT 100
)
DELETE FROM control.share_cookies AS cookie
USING expired WHERE cookie.token_digest = expired.token_digest;

-- name: DeleteFinishedShareHandoffs :exec
WITH finished AS (
    SELECT candidate.token_digest FROM control.share_handoffs AS candidate
    WHERE candidate.expires_at <= sqlc.arg(now) OR candidate.consumed_at IS NOT NULL
    LIMIT 100
)
DELETE FROM control.share_handoffs AS handoff
USING finished WHERE handoff.token_digest = finished.token_digest;
