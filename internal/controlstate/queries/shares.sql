-- name: CreateShare :one
INSERT INTO control.shares (
    id, preview_id, team_id, scope, label, created_by_identity_id,
    idempotency_key, request_digest, secret_digest, created_at, expires_at
) VALUES (sqlc.arg(id), sqlc.narg(preview_id), sqlc.arg(team_id), sqlc.arg(scope), sqlc.arg(label),
    sqlc.arg(created_by_identity_id), sqlc.arg(idempotency_key), sqlc.arg(request_digest),
    sqlc.arg(secret_digest), sqlc.arg(created_at), sqlc.arg(expires_at))
ON CONFLICT (created_by_identity_id, idempotency_key)
DO UPDATE SET idempotency_key = EXCLUDED.idempotency_key
RETURNING *;

-- name: AddSharePublicURL :one
INSERT INTO control.share_public_urls (share_id, team_id, public_url_id)
SELECT g.id, g.team_id, u.id
FROM control.shares g
JOIN control.public_urls u ON u.id = sqlc.arg(public_url_id) AND u.team_id = g.team_id
WHERE g.id = sqlc.arg(share_id) AND g.created_by_identity_id = sqlc.arg(identity_id)
  AND ((g.scope = 'url' AND u.purpose IN ('app', 'alias', 'demo'))
    OR (g.scope = 'preview' AND EXISTS (SELECT 1 FROM control.preview_public_urls p
        WHERE p.preview_id = g.preview_id AND p.team_id = g.team_id AND p.public_url_id = u.id)))
ON CONFLICT (share_id, public_url_id) DO UPDATE SET
    public_url_id = control.share_public_urls.public_url_id
RETURNING public_url_id;

-- name: CreateGuestShare :one
INSERT INTO control.shares (id, team_id, guest_id, scope, created_by_identity_id,
    idempotency_key, request_digest, secret_digest, created_at, expires_at)
SELECT sqlc.arg(id), trial.team_id, trial.id, 'guest', trial.id,
    sqlc.arg(idempotency_key), sqlc.arg(request_digest), sqlc.arg(secret_digest), sqlc.arg(now), trial.expires_at
FROM control.guest_trials trial
JOIN control.guest_public_urls included ON included.guest_id = trial.id AND included.public_url_id = sqlc.arg(public_url_id)
JOIN control.public_urls url ON url.id = included.public_url_id AND url.team_id = trial.team_id
WHERE trial.id = sqlc.arg(guest_id) AND control.guest_share_live(trial.id, sqlc.arg(now))
  AND url.lifecycle_state = 'enabled' AND url.purpose = 'demo' AND url.service_protocol = 'http'
ON CONFLICT (created_by_identity_id, idempotency_key)
DO UPDATE SET idempotency_key = EXCLUDED.idempotency_key
RETURNING *;

-- name: AddGuestSharePublicURL :one
INSERT INTO control.share_public_urls (share_id, team_id, public_url_id)
SELECT share.id, share.team_id, included.public_url_id
FROM control.shares share
JOIN control.guest_public_urls included ON included.guest_id = share.guest_id
JOIN control.public_urls url ON url.id = included.public_url_id AND url.team_id = share.team_id
WHERE share.id = sqlc.arg(share_id) AND share.scope = 'guest'
  AND included.public_url_id = sqlc.arg(public_url_id) AND url.lifecycle_state = 'enabled'
ON CONFLICT (share_id, public_url_id) DO UPDATE SET public_url_id = control.share_public_urls.public_url_id
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

-- name: ListTeamShares :many
SELECT * FROM control.shares
WHERE team_id = sqlc.arg(team_id)
  AND created_by_identity_id = sqlc.arg(identity_id)
  AND id > sqlc.arg(after_id)
ORDER BY id LIMIT 101;

-- name: RevokeShare :one
UPDATE control.shares
SET revoked_at = COALESCE(revoked_at, sqlc.arg(revoked_at)::timestamptz),
    revoked_by_identity_id = COALESCE(revoked_by_identity_id, sqlc.arg(revoked_by_identity_id)::text)
WHERE id = sqlc.arg(share_id)
  AND created_by_identity_id = sqlc.arg(identity_id)
RETURNING *;
