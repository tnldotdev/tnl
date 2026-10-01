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
INSERT INTO control.runtime_secret (
    id,
    external_retry_master_key_ciphertext,
    external_retry_master_key_storage_key_id,
    created_at
) VALUES (
    1,
    sqlc.arg(external_retry_master_key_ciphertext),
    sqlc.arg(external_retry_master_key_storage_key_id),
    sqlc.arg(created_at)
)
ON CONFLICT (id) DO UPDATE SET id = EXCLUDED.id
RETURNING external_retry_master_key_ciphertext, external_retry_master_key_storage_key_id;

-- name: RotateExternalRetryMasterKey :exec
UPDATE control.runtime_secret
SET external_retry_master_key_ciphertext = sqlc.arg(external_retry_master_key_ciphertext),
    external_retry_master_key_storage_key_id = sqlc.arg(external_retry_master_key_storage_key_id)
WHERE id = 1
  AND external_retry_master_key_storage_key_id = sqlc.arg(previous_key_id)
  AND external_retry_master_key_ciphertext = sqlc.arg(previous_ciphertext);

-- name: ObserveAuthorityRevision :one
INSERT INTO control.authority_revision_states (
    issuer,
    team_id,
    observed_policy_revision,
    observed_at
) VALUES (
    sqlc.arg(issuer),
    sqlc.arg(team_id),
    sqlc.arg(policy_revision),
    sqlc.arg(updated_at)
)
ON CONFLICT (issuer, team_id) DO UPDATE SET
    observed_policy_revision = EXCLUDED.observed_policy_revision,
    observed_at = GREATEST(control.authority_revision_states.observed_at, EXCLUDED.observed_at)
WHERE GREATEST(
    control.authority_revision_states.observed_policy_revision,
    control.authority_revision_states.applied_policy_revision
) <= EXCLUDED.observed_policy_revision
RETURNING observed_policy_revision;

-- name: AdvanceAuthorityRevision :one
INSERT INTO control.authority_revision_states (
    issuer,
    team_id,
    observed_policy_revision,
    applied_policy_revision,
    observed_at,
    applied_at
) VALUES (
    sqlc.arg(issuer),
    sqlc.arg(team_id),
    sqlc.arg(policy_revision),
    sqlc.arg(policy_revision),
    sqlc.arg(updated_at),
    sqlc.arg(updated_at)
)
ON CONFLICT (issuer, team_id) DO UPDATE SET
    observed_policy_revision = GREATEST(
        control.authority_revision_states.observed_policy_revision,
        EXCLUDED.observed_policy_revision
    ),
    applied_policy_revision = EXCLUDED.applied_policy_revision,
    observed_at = GREATEST(control.authority_revision_states.observed_at, EXCLUDED.observed_at),
    applied_at = GREATEST(control.authority_revision_states.applied_at, EXCLUDED.applied_at)
WHERE control.authority_revision_states.applied_policy_revision < EXCLUDED.applied_policy_revision
RETURNING applied_policy_revision;

-- name: LockHostedTeamPublicURLs :many
SELECT *
FROM control.public_urls
WHERE team_id = sqlc.arg(team_id)
  AND deleted_at IS NULL
ORDER BY id
FOR UPDATE;

-- name: ListExternalAuthorityPublicURLs :many
SELECT routes.*,
    COALESCE((
        SELECT sessions.id
        FROM control.publish_runs AS sessions
        WHERE sessions.public_url_id = routes.id
          AND sessions.closed_at IS NULL
    ), '')::text AS open_publish_run_id
FROM control.public_urls AS routes
WHERE routes.team_id = sqlc.arg(team_id)
  AND routes.lifecycle_state <> 'deleted'
  AND (sqlc.narg(cursor)::text IS NULL OR routes.id > sqlc.narg(cursor))
ORDER BY routes.id
LIMIT 101;

-- name: GetExternalAuthorityPublicURL :one
SELECT routes.*,
    COALESCE((
        SELECT sessions.id
        FROM control.publish_runs AS sessions
        WHERE sessions.public_url_id = routes.id
          AND sessions.closed_at IS NULL
    ), '')::text AS open_publish_run_id,
    COALESCE((
        SELECT sessions.publish_run_number
        FROM control.publish_runs AS sessions
        WHERE sessions.public_url_id = routes.id
          AND sessions.idempotency_key = sqlc.arg(publish_run_idempotency_key)
    ), routes.next_publish_run_number)::bigint AS authorization_publish_run_number
FROM control.public_urls AS routes
WHERE routes.id = sqlc.arg(public_url_id)
  AND routes.lifecycle_state <> 'deleted';

-- name: GetAuthorizedPublicURLByHostname :one
SELECT routes.*,
    COALESCE((
        SELECT sessions.id
        FROM control.publish_runs AS sessions
        WHERE sessions.public_url_id = routes.id
          AND sessions.closed_at IS NULL
    ), '')::text AS open_publish_run_id
FROM control.public_urls AS routes
WHERE routes.team_id = sqlc.arg(team_id)
  AND routes.canonical_hostname = sqlc.arg(canonical_hostname)
  AND routes.lifecycle_state <> 'deleted';
