-- name: EnsureVisitorTokenIssuer :one
INSERT INTO control.visitor_token_issuer(issuer) VALUES(sqlc.arg(issuer))
ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id RETURNING issuer;

-- name: ShareVisitorTokenIssuer :one
SELECT issuer FROM control.visitor_token_issuer WHERE id FOR SHARE;

-- name: ShareVisitorTokenSigningKey :one
SELECT * FROM control.visitor_token_keys WHERE retired_at IS NULL AND revoked_at IS NULL FOR SHARE;

-- name: CreateVisitorTokenSigningKey :one
INSERT INTO control.visitor_token_keys(id,public_key,seed_ciphertext,storage_key_id,created_at,retain_until)
VALUES(sqlc.arg(id),sqlc.arg(public_key),sqlc.arg(seed_ciphertext),sqlc.arg(storage_key_id),sqlc.arg(now),sqlc.arg(retain_until)) RETURNING *;

-- name: RetainVisitorTokenSigningKey :execrows
UPDATE control.visitor_token_keys SET retain_until=GREATEST(retain_until,sqlc.arg(retain_until))
WHERE retired_at IS NULL AND revoked_at IS NULL AND retain_until<sqlc.arg(expires_at);

-- name: RetireVisitorTokenSigningKeys :exec
UPDATE control.visitor_token_keys SET retired_at=COALESCE(retired_at,sqlc.arg(now))
WHERE retired_at IS NULL AND revoked_at IS NULL;

-- name: RevokeVisitorTokenSigningKeys :exec
UPDATE control.visitor_token_keys SET revoked_at=COALESCE(revoked_at,sqlc.arg(now))
WHERE revoked_at IS NULL;

-- name: VisitorTokenVerificationKeys :many
SELECT id,public_key FROM control.visitor_token_keys
WHERE revoked_at IS NULL AND (retired_at IS NULL OR retain_until>sqlc.arg(now))
ORDER BY created_at,id LIMIT 65;

-- name: DeleteExpiredVisitorTokenSigningKeys :exec
DELETE FROM control.visitor_token_keys WHERE retain_until<=sqlc.arg(now) AND (retired_at IS NOT NULL OR revoked_at IS NOT NULL);
