-- name: InsertBrowserLoginAttempt :exec
INSERT INTO control.browser_login_attempts
    (state_digest, binding_digest, preview_id, public_url_id, return_path, nonce, verifier_ciphertext, verifier_storage_key_id, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: ConsumeBrowserLoginAttempt :one
UPDATE control.browser_login_attempts
SET consumed_at = sqlc.arg(now)
WHERE state_digest = sqlc.arg(state_digest) AND binding_digest = sqlc.arg(binding_digest)
  AND consumed_at IS NULL AND expires_at > sqlc.arg(now)
RETURNING preview_id, public_url_id, return_path, nonce, verifier_ciphertext, verifier_storage_key_id;

-- name: InsertBrowserAccessSession :exec
INSERT INTO control.browser_access_sessions
    (token_digest, preview_id, public_url_id, identity_id, display_name, access_ciphertext, refresh_ciphertext, storage_key_id, access_expires_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: GetBrowserAccessSession :one
SELECT token_digest, preview_id, public_url_id, identity_id, display_name,
       access_ciphertext, refresh_ciphertext, storage_key_id, access_expires_at, expires_at, revoked_at
FROM control.browser_access_sessions WHERE token_digest = $1;

-- name: BrowserSessionPublicURLIncluded :one
SELECT included.public_url_id
FROM control.browser_access_sessions AS session
JOIN control.preview_public_urls AS included ON included.preview_id = session.preview_id
WHERE session.token_digest = sqlc.arg(token_digest) AND included.public_url_id = sqlc.arg(public_url_id);

-- name: ListReadyPreviewBrowserHostnames :many
SELECT url.id AS public_url_id, url.canonical_hostname
FROM control.preview_public_urls AS included
JOIN control.public_urls AS url ON url.id = included.public_url_id
JOIN control.publish_runs AS run ON run.public_url_id = url.id
WHERE included.preview_id = sqlc.arg(preview_id)
  AND url.lifecycle_state = 'enabled'
  AND run.state = 'ready' AND run.publisher_expires_at > sqlc.arg(now)
  AND run.share_capable = true
ORDER BY url.id LIMIT 32;

-- name: LockBrowserAccessSession :one
SELECT token_digest, preview_id, public_url_id, identity_id, display_name,
       access_ciphertext, refresh_ciphertext, storage_key_id, access_expires_at, expires_at, revoked_at
FROM control.browser_access_sessions WHERE token_digest = $1 FOR UPDATE;

-- name: ShareBrowserAccessSession :one
SELECT session.*
FROM control.browser_access_sessions AS session
JOIN control.preview_public_urls AS included ON included.preview_id = session.preview_id
WHERE session.token_digest = sqlc.arg(token_digest)
  AND included.public_url_id = sqlc.arg(public_url_id)
FOR SHARE OF session, included;

-- name: ShareBrowserControlIdentity :one
SELECT session.identity_id, identity.display_name, session.access_token_digest,
       session.access_expires_at, session.refresh_expires_at
FROM control.control_sessions AS session
JOIN control.identities AS identity ON identity.id = session.identity_id
WHERE session.access_token_id = sqlc.arg(access_token_id)
  AND session.authentication_method = 'oidc'
  AND session.revoked_at IS NULL AND identity.disabled_at IS NULL
FOR SHARE OF session, identity;

-- name: ShareBrowserPublicURL :one
SELECT * FROM control.public_urls WHERE id = sqlc.arg(public_url_id) FOR SHARE;

-- name: RotateBrowserAccessSession :exec
UPDATE control.browser_access_sessions
SET access_ciphertext = sqlc.arg(access_ciphertext), refresh_ciphertext = sqlc.arg(refresh_ciphertext),
    access_expires_at = sqlc.arg(access_expires_at), storage_key_id = sqlc.arg(storage_key_id)
WHERE token_digest = sqlc.arg(token_digest) AND revoked_at IS NULL;

-- name: RevokeBrowserAccessSession :exec
UPDATE control.browser_access_sessions SET revoked_at = sqlc.arg(now)
WHERE token_digest = sqlc.arg(token_digest) AND revoked_at IS NULL
  AND EXISTS (SELECT 1 FROM control.preview_public_urls AS included
              WHERE included.preview_id = control.browser_access_sessions.preview_id
                AND included.public_url_id = sqlc.arg(public_url_id));

-- name: InsertBrowserAccessHandoff :exec
INSERT INTO control.browser_access_handoffs
    (token_digest, session_digest, public_url_id, cookie_ciphertext, storage_key_id, return_path, next_url, bridge, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: ConsumeBrowserAccessHandoff :one
UPDATE control.browser_access_handoffs AS handoff
SET consumed_at = sqlc.arg(now)
FROM control.browser_access_sessions AS session
WHERE handoff.token_digest = sqlc.arg(token_digest) AND handoff.public_url_id = sqlc.arg(public_url_id)
  AND handoff.consumed_at IS NULL AND handoff.expires_at > sqlc.arg(now)
  AND session.token_digest = handoff.session_digest AND session.revoked_at IS NULL AND session.expires_at > sqlc.arg(now)
RETURNING handoff.session_digest, handoff.cookie_ciphertext, handoff.storage_key_id, handoff.return_path,
          handoff.next_url, handoff.bridge, session.expires_at;

-- name: CleanupBrowserAccess :exec
DELETE FROM control.browser_login_attempts WHERE expires_at < sqlc.arg(now);
