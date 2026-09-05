-- name: EnsureExternalAuthorityPrincipal :one
INSERT INTO control.identities (
    id,
    kind,
    display_name,
    administrator,
    created_at,
    updated_at
) VALUES (
    sqlc.arg(identity_id),
    'authority',
    sqlc.arg(identity_id),
    false,
    sqlc.arg(created_at),
    sqlc.arg(created_at)
)
ON CONFLICT (id) DO UPDATE SET
    updated_at = GREATEST(control.identities.updated_at, EXCLUDED.updated_at)
WHERE control.identities.kind = 'authority'
  AND control.identities.disabled_at IS NULL
RETURNING *;

-- name: EnsureExternalRetryMasterKey :one
INSERT INTO control.runtime_secrets (
    singleton,
    external_retry_master_key_ciphertext,
    external_retry_master_key_storage_key_id,
    created_at
) VALUES (
    true,
    sqlc.arg(external_retry_master_key_ciphertext),
    sqlc.arg(external_retry_master_key_storage_key_id),
    sqlc.arg(created_at)
)
ON CONFLICT (singleton) DO UPDATE SET singleton = EXCLUDED.singleton
RETURNING external_retry_master_key_ciphertext, external_retry_master_key_storage_key_id;

-- name: RotateExternalRetryMasterKey :exec
UPDATE control.runtime_secrets
SET external_retry_master_key_ciphertext = sqlc.arg(external_retry_master_key_ciphertext),
    external_retry_master_key_storage_key_id = sqlc.arg(external_retry_master_key_storage_key_id)
WHERE singleton = true
  AND external_retry_master_key_storage_key_id = sqlc.arg(previous_key_id)
  AND external_retry_master_key_ciphertext = sqlc.arg(previous_ciphertext);

-- name: ObserveAuthorityRevision :one
INSERT INTO control.authority_revision_floors (
    issuer,
    team_id,
    policy_revision,
    updated_at
) VALUES (
    sqlc.arg(issuer),
    sqlc.arg(team_id),
    sqlc.arg(policy_revision),
    sqlc.arg(updated_at)
)
ON CONFLICT (issuer, team_id) DO UPDATE SET
    policy_revision = EXCLUDED.policy_revision,
    updated_at = EXCLUDED.updated_at
WHERE control.authority_revision_floors.policy_revision <= EXCLUDED.policy_revision
RETURNING policy_revision;

-- name: AdvanceAuthorityRevision :one
INSERT INTO control.authority_revision_floors (
    issuer,
    team_id,
    policy_revision,
    updated_at
) VALUES (
    sqlc.arg(issuer),
    sqlc.arg(team_id),
    sqlc.arg(policy_revision),
    sqlc.arg(updated_at)
)
ON CONFLICT (issuer, team_id) DO UPDATE SET
    policy_revision = EXCLUDED.policy_revision,
    updated_at = GREATEST(control.authority_revision_floors.updated_at, EXCLUDED.updated_at)
WHERE control.authority_revision_floors.policy_revision < EXCLUDED.policy_revision
RETURNING policy_revision;

-- name: LockHostedTeamRoutes :many
SELECT *
FROM control.routes
WHERE team_id = sqlc.arg(team_id)
  AND deleted_at IS NULL
ORDER BY id
FOR UPDATE;

-- name: ListExternalAuthorityRoutes :many
SELECT routes.*,
    COALESCE((
        SELECT sessions.id
        FROM control.route_sessions AS sessions
        WHERE sessions.route_id = routes.id
          AND sessions.closed_at IS NULL
    ), '')::text AS attached_session_id
FROM control.routes AS routes
WHERE routes.team_id = sqlc.arg(team_id)
  AND routes.lifecycle_state <> 'deleted'
  AND (sqlc.narg(cursor)::text IS NULL OR routes.id > sqlc.narg(cursor))
ORDER BY routes.id
LIMIT 101;

-- name: GetExternalAuthorityRoute :one
SELECT routes.*,
    COALESCE((
        SELECT sessions.id
        FROM control.route_sessions AS sessions
        WHERE sessions.route_id = routes.id
          AND sessions.closed_at IS NULL
    ), '')::text AS attached_session_id
FROM control.routes AS routes
WHERE routes.id = sqlc.arg(route_id)
  AND routes.lifecycle_state <> 'deleted';
