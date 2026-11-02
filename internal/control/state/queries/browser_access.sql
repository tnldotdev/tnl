-- name: InsertBrowserLoginAttempt :exec
WITH inserted AS (
INSERT INTO control.browser_login_attempts
    (state_digest, binding_digest, preview_id, public_url_id, publish_run_id, return_path, nonce, verifier_ciphertext, verifier_storage_key_id, expires_at)
VALUES ($1, $2, sqlc.narg(preview_id), $3, $4, $5, $6, $7, $8, $9) RETURNING state_digest,public_url_id
)
INSERT INTO control.browser_login_run_bindings(state_digest,publish_run_id)
SELECT inserted.state_digest,run.id FROM inserted JOIN control.publish_runs run ON run.public_url_id=inserted.public_url_id
WHERE run.state='ready' AND run.closed_at IS NULL AND run.publisher_expires_at>sqlc.arg(now);

-- name: ConsumeBrowserLoginAttempt :one
UPDATE control.browser_login_attempts attempt
SET consumed_at = sqlc.arg(now),publish_run_id=(SELECT run.id FROM control.browser_login_run_bindings bound JOIN control.publish_runs run ON run.id=bound.publish_run_id
    WHERE bound.state_digest=attempt.state_digest AND run.public_url_id=attempt.public_url_id AND run.state='ready' AND run.closed_at IS NULL AND run.publisher_expires_at>sqlc.arg(now)
    ORDER BY run.publish_run_number LIMIT 1)
WHERE attempt.state_digest = sqlc.arg(state_digest) AND attempt.binding_digest = sqlc.arg(binding_digest)
  AND attempt.consumed_at IS NULL AND attempt.expires_at > sqlc.arg(now)
  AND EXISTS(SELECT 1 FROM control.browser_login_run_bindings bound JOIN control.publish_runs run ON run.id=bound.publish_run_id
    WHERE bound.state_digest=attempt.state_digest AND run.public_url_id=attempt.public_url_id AND run.state='ready' AND run.closed_at IS NULL AND run.publisher_expires_at>sqlc.arg(now))
RETURNING attempt.preview_id, attempt.public_url_id, attempt.publish_run_id, attempt.return_path, attempt.nonce, attempt.verifier_ciphertext, attempt.verifier_storage_key_id;

-- name: InsertBrowserAccessSession :exec
INSERT INTO control.browser_access_sessions
    (token_digest, preview_id, public_url_id, identity_id, display_name, access_ciphertext, refresh_ciphertext, storage_key_id, access_expires_at, expires_at, parent_control_session_id)
VALUES ($1, sqlc.narg(preview_id), $2, $3, $4, $5, $6, $7, $8, $9, sqlc.narg(parent_control_session_id));

-- name: GetBrowserAccessSession :one
SELECT token_digest, preview_id, public_url_id, identity_id, display_name,
       access_ciphertext, refresh_ciphertext, storage_key_id, access_expires_at, expires_at, revoked_at, parent_control_session_id
FROM control.browser_access_sessions WHERE token_digest = $1;

-- name: BrowserSessionPublicURLIncluded :one
SELECT included.public_url_id
FROM control.browser_access_sessions AS session
JOIN control.browser_session_run_bindings AS included ON included.session_digest = session.token_digest
WHERE session.token_digest = sqlc.arg(token_digest) AND included.public_url_id = sqlc.arg(public_url_id);

-- name: LockBrowserAccessSession :one
SELECT token_digest, preview_id, public_url_id, identity_id, display_name,
       access_ciphertext, refresh_ciphertext, storage_key_id, access_expires_at, expires_at, revoked_at, parent_control_session_id
FROM control.browser_access_sessions WHERE token_digest = $1 FOR UPDATE;

-- name: RotateBrowserAccessSession :exec
UPDATE control.browser_access_sessions
SET access_ciphertext = sqlc.arg(access_ciphertext), refresh_ciphertext = sqlc.arg(refresh_ciphertext),
    access_expires_at = sqlc.arg(access_expires_at), storage_key_id = sqlc.arg(storage_key_id)
WHERE token_digest = sqlc.arg(token_digest) AND revoked_at IS NULL;

-- name: RevokeBrowserAccessSession :exec
UPDATE control.browser_access_sessions SET revoked_at = sqlc.arg(now)
WHERE token_digest = sqlc.arg(token_digest) AND revoked_at IS NULL
   AND EXISTS (SELECT 1 FROM control.browser_session_run_bindings AS included
               WHERE included.session_digest = control.browser_access_sessions.token_digest
                AND included.public_url_id = sqlc.arg(public_url_id));

-- name: InsertBrowserAccessHandoff :exec
WITH inserted AS (
INSERT INTO control.browser_access_handoffs
    (token_digest, session_digest, public_url_id, publish_run_id, cookie_ciphertext, storage_key_id, return_path, redirect_url, bridge, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING token_digest,public_url_id
)
INSERT INTO control.browser_handoff_run_bindings(handoff_digest,publish_run_id)
SELECT inserted.token_digest,run.id FROM inserted JOIN control.publish_runs run ON run.public_url_id=inserted.public_url_id
WHERE run.state='ready' AND run.closed_at IS NULL AND run.publisher_expires_at>sqlc.arg(now);

-- name: ConsumeBrowserAccessHandoff :one
UPDATE control.browser_access_handoffs AS handoff
SET consumed_at = sqlc.arg(now)
FROM control.browser_access_sessions AS session
WHERE handoff.token_digest = sqlc.arg(token_digest) AND handoff.public_url_id = sqlc.arg(public_url_id)
   AND EXISTS(SELECT 1 FROM control.browser_handoff_run_bindings bound WHERE bound.handoff_digest=handoff.token_digest AND bound.publish_run_id=sqlc.arg(publish_run_id))
  AND handoff.consumed_at IS NULL AND handoff.expires_at > sqlc.arg(now)
  AND session.token_digest = handoff.session_digest AND session.revoked_at IS NULL AND session.expires_at > sqlc.arg(now)
RETURNING handoff.session_digest, handoff.cookie_ciphertext, handoff.storage_key_id, handoff.return_path,
           handoff.redirect_url, handoff.bridge, session.expires_at, handoff.publish_run_id;

-- name: CleanupBrowserAccess :exec
DELETE FROM control.browser_login_attempts WHERE expires_at < sqlc.arg(now);
