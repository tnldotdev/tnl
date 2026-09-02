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

-- name: InsertAccessCredential :exec
INSERT INTO access_credentials (
    id,
    identity_id,
    secret_hash,
    created_at,
    expires_at
) VALUES (
    sqlc.arg(credential_id),
    sqlc.arg(identity_id),
    sqlc.arg(secret_hash),
    sqlc.arg(created_at),
    sqlc.arg(expires_at)
);

-- name: GetAccessCredential :one
SELECT
    p.id AS identity_id,
    p.display_name,
    p.email,
    c.secret_hash,
    c.expires_at,
    c.revoked_at
FROM access_credentials AS c
JOIN identities AS p ON p.id = c.identity_id
WHERE c.id = sqlc.arg(credential_id);

-- name: RevokeAccessCredential :execrows
UPDATE access_credentials
SET revoked_at = COALESCE(revoked_at, CAST(sqlc.arg(revoked_at) AS INTEGER))
WHERE id = sqlc.arg(credential_id)
  AND identity_id = sqlc.arg(identity_id);
