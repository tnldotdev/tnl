-- name: CreateShare :one
INSERT INTO control.shares (
    id, preview_id, team_id, created_by_identity_id,
    idempotency_key, request_digest, secret_fingerprint, created_at, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (created_by_identity_id, idempotency_key)
DO UPDATE SET idempotency_key = EXCLUDED.idempotency_key
RETURNING *;

-- name: AddSharePublicURL :one
INSERT INTO control.share_public_urls (share_id, team_id, public_url_id)
SELECT g.id, g.team_id, p.public_url_id
FROM control.shares g
JOIN control.preview_public_urls p ON p.preview_id = g.preview_id
    AND p.team_id = g.team_id AND p.public_url_id = sqlc.arg(public_url_id)
WHERE g.id = sqlc.arg(share_id) AND g.created_by_identity_id = sqlc.arg(identity_id)
ON CONFLICT (share_id, public_url_id) DO UPDATE SET
    public_url_id = control.share_public_urls.public_url_id
RETURNING public_url_id;

-- name: GetShare :one
SELECT * FROM control.shares WHERE id = $1;

-- name: ListSharePublicURLs :many
SELECT public_url_id FROM control.share_public_urls
WHERE share_id = $1 ORDER BY public_url_id;

-- name: ListShares :many
SELECT * FROM control.shares
WHERE preview_id = sqlc.arg(preview_id)
  AND id > sqlc.arg(after_id)
ORDER BY id LIMIT 101;

-- name: RevokeShare :one
UPDATE control.shares
SET revoked_at = COALESCE(revoked_at, sqlc.arg(revoked_at)::timestamptz),
    revoked_by_identity_id = COALESCE(revoked_by_identity_id, sqlc.arg(revoked_by_identity_id)::text)
WHERE id = sqlc.arg(share_id)
  AND created_by_identity_id = sqlc.arg(identity_id)
RETURNING *;
