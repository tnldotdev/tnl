-- name: UpsertIdentity :exec
INSERT INTO identities (
    id,
    display_name,
    email,
    created_at
) VALUES (
    sqlc.arg(identity_id),
    sqlc.arg(display_name),
    sqlc.arg(email),
    sqlc.arg(created_at)
)
ON CONFLICT (id) DO UPDATE SET
    display_name = excluded.display_name,
    email = excluded.email;

-- name: DeleteExpiredOIDCAssertions :exec
DELETE FROM oidc_assertion_exchanges
WHERE expires_at <= sqlc.arg(issued_at);

-- name: ConsumeOIDCAssertion :execrows
INSERT INTO oidc_assertion_exchanges (
    assertion_hash,
    consumed_at,
    expires_at
) VALUES (
    sqlc.arg(assertion_hash),
    sqlc.arg(consumed_at),
    sqlc.arg(expires_at)
)
ON CONFLICT (assertion_hash) DO NOTHING;

-- name: InsertControlSession :exec
INSERT INTO control_sessions (
    id,
    identity_id,
    authentication_method,
    authentication_source_revision,
    grants,
    created_at,
    refresh_expires_at,
    access_token_id,
    access_token_hash,
    access_expires_at,
    refresh_token_id,
    refresh_token_hash
) VALUES (
    sqlc.arg(session_id),
    sqlc.arg(identity_id),
    sqlc.arg(authentication_method),
    sqlc.arg(authentication_source_revision),
    sqlc.arg(grants),
    sqlc.arg(created_at),
    sqlc.arg(refresh_expires_at),
    sqlc.arg(access_token_id),
    sqlc.arg(access_token_hash),
    sqlc.arg(access_expires_at),
    sqlc.arg(refresh_token_id),
    sqlc.arg(refresh_token_hash)
);

-- name: GetControlSessionByAccessToken :one
SELECT
    c.id AS session_id,
    p.id AS identity_id,
    p.display_name,
    p.email,
    c.grants,
    c.access_token_hash,
    c.access_expires_at,
    c.access_token_revoked_at,
    c.revoked_at
FROM control_sessions AS c
JOIN identities AS p ON p.id = c.identity_id
WHERE c.access_token_id = sqlc.arg(access_token_id);

-- name: GetControlSessionByRefreshToken :one
SELECT
    id AS session_id,
    identity_id,
    grants,
    refresh_token_hash,
    refresh_expires_at,
    refresh_token_revoked_at,
    revoked_at
FROM control_sessions
WHERE refresh_token_id = sqlc.arg(refresh_token_id);

-- name: GetReplacedControlSessionRefreshToken :one
SELECT
    h.session_id,
    h.token_hash,
    c.revoked_at
FROM control_session_refresh_tokens AS h
JOIN control_sessions AS c ON c.id = h.session_id
WHERE h.token_id = sqlc.arg(refresh_token_id);

-- name: InsertReplacedControlSessionRefreshToken :exec
INSERT INTO control_session_refresh_tokens (
    token_id,
    session_id,
    token_hash,
    replaced_at
) VALUES (
    sqlc.arg(refresh_token_id),
    sqlc.arg(session_id),
    sqlc.arg(token_hash),
    sqlc.arg(replaced_at)
);

-- name: RotateControlSessionTokens :execrows
UPDATE control_sessions
SET access_token_id = sqlc.arg(access_token_id),
    access_token_hash = sqlc.arg(access_token_hash),
    access_expires_at = sqlc.arg(access_expires_at),
    access_token_revoked_at = NULL,
    refresh_token_id = sqlc.arg(refresh_token_id),
    refresh_token_hash = sqlc.arg(refresh_token_hash),
    refresh_token_revoked_at = NULL
WHERE id = sqlc.arg(session_id)
  AND refresh_token_id = sqlc.arg(previous_refresh_token_id)
  AND revoked_at IS NULL
  AND refresh_token_revoked_at IS NULL;

-- name: RevokeControlSession :execrows
UPDATE control_sessions
SET access_token_revoked_at = COALESCE(access_token_revoked_at, CAST(sqlc.arg(revoked_at) AS INTEGER)),
    refresh_token_revoked_at = COALESCE(refresh_token_revoked_at, CAST(sqlc.arg(revoked_at) AS INTEGER)),
    revoked_at = COALESCE(revoked_at, CAST(sqlc.arg(revoked_at) AS INTEGER))
WHERE id = sqlc.arg(session_id);

-- name: RevokeOwnedControlSession :execrows
UPDATE control_sessions
SET access_token_revoked_at = COALESCE(access_token_revoked_at, CAST(sqlc.arg(revoked_at) AS INTEGER)),
    refresh_token_revoked_at = COALESCE(refresh_token_revoked_at, CAST(sqlc.arg(revoked_at) AS INTEGER)),
    revoked_at = COALESCE(revoked_at, CAST(sqlc.arg(revoked_at) AS INTEGER))
WHERE id = sqlc.arg(session_id)
  AND identity_id = sqlc.arg(identity_id);

-- name: RevokeControlSessionsByAuthenticationSource :execrows
UPDATE control_sessions
SET access_token_revoked_at = COALESCE(access_token_revoked_at, CAST(sqlc.arg(revoked_at) AS INTEGER)),
    refresh_token_revoked_at = COALESCE(refresh_token_revoked_at, CAST(sqlc.arg(revoked_at) AS INTEGER)),
    revoked_at = COALESCE(revoked_at, CAST(sqlc.arg(revoked_at) AS INTEGER))
WHERE authentication_method = sqlc.arg(authentication_method)
  AND authentication_source_revision < sqlc.arg(authentication_source_revision)
  AND revoked_at IS NULL;

-- name: RevokeExpiredControlSessions :execrows
UPDATE control_sessions
SET access_token_revoked_at = COALESCE(access_token_revoked_at, CAST(sqlc.arg(revoked_at) AS INTEGER)),
    refresh_token_revoked_at = COALESCE(refresh_token_revoked_at, CAST(sqlc.arg(revoked_at) AS INTEGER)),
    revoked_at = COALESCE(revoked_at, CAST(sqlc.arg(revoked_at) AS INTEGER))
WHERE refresh_expires_at <= sqlc.arg(revoked_at)
  AND revoked_at IS NULL;

-- name: RevokeExcessControlSessions :execrows
UPDATE control_sessions
SET access_token_revoked_at = COALESCE(access_token_revoked_at, CAST(sqlc.arg(revoked_at) AS INTEGER)),
    refresh_token_revoked_at = COALESCE(refresh_token_revoked_at, CAST(sqlc.arg(revoked_at) AS INTEGER)),
    revoked_at = COALESCE(revoked_at, CAST(sqlc.arg(revoked_at) AS INTEGER))
WHERE id IN (
    SELECT candidate.id
    FROM control_sessions AS candidate
    WHERE candidate.identity_id = sqlc.arg(identity_id)
      AND candidate.refresh_expires_at > sqlc.arg(revoked_at)
      AND candidate.revoked_at IS NULL
    ORDER BY candidate.created_at DESC, candidate.rowid DESC
    LIMIT -1 OFFSET sqlc.arg(max_active_sessions)
);

-- name: DeleteInactiveControlSessionRefreshTokens :exec
DELETE FROM control_session_refresh_tokens
WHERE session_id IN (
    SELECT id
    FROM control_sessions
    WHERE revoked_at IS NOT NULL
       OR refresh_expires_at <= sqlc.arg(now)
);
