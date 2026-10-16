-- control-host identity sessions are shared by browser approval pages. the
-- cookie is random, host-only, Secure and HttpOnly; store only its SHA-256.
-- name: InsertBrowserIdentityLoginAttempt :exec
INSERT INTO control.browser_identity_login_attempts
    (state_digest, binding_digest, nonce, verifier_ciphertext, verifier_storage_key_id, created_at, expires_at)
VALUES (sqlc.arg(state_digest), sqlc.arg(binding_digest), sqlc.arg(nonce),
        sqlc.arg(verifier_ciphertext), sqlc.arg(verifier_storage_key_id),
        sqlc.arg(created_at), sqlc.arg(expires_at));

-- name: ConsumeBrowserIdentityLoginAttempt :one
UPDATE control.browser_identity_login_attempts SET consumed_at = sqlc.arg(now)
WHERE state_digest = sqlc.arg(state_digest) AND binding_digest = sqlc.arg(binding_digest)
  AND consumed_at IS NULL AND expires_at > sqlc.arg(now)
RETURNING nonce, verifier_ciphertext, verifier_storage_key_id;

-- name: CleanupBrowserIdentityLogins :exec
DELETE FROM control.browser_identity_login_attempts AS stored WHERE stored.state_digest IN
    (SELECT expired.state_digest FROM control.browser_identity_login_attempts AS expired
     WHERE expired.expires_at <= sqlc.arg(now) LIMIT 100);

-- name: InsertBrowserIdentitySession :exec
INSERT INTO control.browser_identity_sessions
    (cookie_digest, identity_id, parent_control_session_id, access_ciphertext, refresh_ciphertext,
     storage_key_id, access_expires_at, created_at, expires_at)
VALUES (sqlc.arg(cookie_digest), sqlc.arg(identity_id), sqlc.narg(parent_control_session_id),
        sqlc.arg(access_ciphertext), sqlc.arg(refresh_ciphertext), sqlc.arg(storage_key_id),
        sqlc.arg(access_expires_at), sqlc.arg(created_at), sqlc.arg(expires_at));

-- name: LockBrowserIdentitySession :one
SELECT s.* FROM control.browser_identity_sessions AS s
JOIN control.identities AS i ON i.id = s.identity_id AND i.disabled_at IS NULL
LEFT JOIN control.control_sessions AS parent ON parent.id = s.parent_control_session_id
WHERE s.cookie_digest = sqlc.arg(cookie_digest) AND s.revoked_at IS NULL
  AND s.expires_at > sqlc.arg(now)
  AND (s.parent_control_session_id IS NULL OR (parent.revoked_at IS NULL AND parent.refresh_expires_at > sqlc.arg(now)))
FOR UPDATE OF s;

-- name: RotateBrowserIdentitySession :execrows
UPDATE control.browser_identity_sessions
SET access_ciphertext = sqlc.arg(access_ciphertext), refresh_ciphertext = sqlc.arg(refresh_ciphertext),
    storage_key_id = sqlc.arg(storage_key_id), access_expires_at = sqlc.arg(access_expires_at)
WHERE cookie_digest = sqlc.arg(cookie_digest) AND revoked_at IS NULL
  AND control.browser_identity_sessions.expires_at > sqlc.arg(now);

-- name: RevokeBrowserIdentitySession :execrows
UPDATE control.browser_identity_sessions SET revoked_at = sqlc.arg(now)
WHERE cookie_digest = sqlc.arg(cookie_digest) AND revoked_at IS NULL;

-- name: RevokeChildBrowserIdentitySessions :exec
UPDATE control.browser_identity_sessions SET revoked_at = sqlc.arg(now)
WHERE parent_control_session_id = sqlc.arg(parent_control_session_id) AND revoked_at IS NULL;

-- name: CleanupBrowserIdentitySessions :exec
DELETE FROM control.browser_identity_sessions AS stored WHERE stored.cookie_digest IN
    (SELECT expired.cookie_digest FROM control.browser_identity_sessions AS expired
     WHERE expired.expires_at <= sqlc.arg(now) OR expired.revoked_at IS NOT NULL LIMIT 100);
