-- name: LockPublicURLCreator :one
SELECT id
FROM control.identities
WHERE id = sqlc.arg(identity_id)
  AND disabled_at IS NULL
-- serialize creators without blocking publish run and audit foreign-key checks.
FOR NO KEY UPDATE;

-- name: GetPublicURLByCreatorIdempotency :one
SELECT r.*,
    COALESCE((
        SELECT s.id
        FROM control.publish_runs AS s
        WHERE s.public_url_id = r.id
          AND s.closed_at IS NULL
    ), '')::text AS open_publish_run_id
FROM control.public_urls AS r
WHERE r.created_by_identity_id = sqlc.arg(identity_id)
  AND r.idempotency_key = sqlc.arg(idempotency_key);

-- name: LockPublicURLCreationControl :one
SELECT allowed
FROM control.maintenance_controls
WHERE control_name = 'public_url_creation'
FOR SHARE;

-- name: GetPublicURLCreationContext :one
SELECT
    t.kind AS team_kind,
    t.display_name AS team_display_name,
    t.created_by_identity_id AS team_creator_identity_id,
    t.policy_revision,
    i.kind AS identity_kind,
    m.id AS actor_membership_id,
    m.role AS actor_role,
    m.managed_label AS actor_managed_label,
    s.member_slug AS actor_member_slug,
    d.kind AS domain_kind,
    d.team_id AS domain_team_id,
    d.canonical_domain,
    d.state AS domain_state,
    d.dns_authority_reference
FROM control.teams AS t
JOIN control.identities AS i
  ON i.id = sqlc.arg(identity_id)
 AND i.disabled_at IS NULL
JOIN control.team_memberships AS m
  ON m.team_id = t.id
 AND m.identity_id = i.id
 AND m.removed_at IS NULL
JOIN control.member_slug_reservations AS s
  ON s.id = m.slug_reservation_id
JOIN control.domains AS d
  ON d.id = sqlc.arg(domain_id)
 AND d.released_at IS NULL
WHERE t.id = sqlc.arg(team_id)
  AND t.deleted_at IS NULL
FOR SHARE OF t, i, m, s, d;

-- name: ListTeamNamespaceLabels :many
SELECT m.managed_label, s.member_slug
FROM control.team_memberships AS m
JOIN control.member_slug_reservations AS s ON s.id = m.slug_reservation_id
WHERE m.team_id = sqlc.arg(team_id)
  AND m.removed_at IS NULL;

-- name: InsertPublicURL :one
INSERT INTO control.public_urls (
    id,
    team_id,
    domain_id,
    membership_id,
    created_by_identity_id,
    idempotency_key,
    request_digest_ciphertext,
    request_digest_storage_key_id,
    canonical_hostname,
    namespace,
    target,
    public_url_scope,
    policy_revision,
    ip_policy,
    allowed_ip_policy_ciphertext,
    allowed_ip_policy_storage_key_id,
    allowed_ip_hashes,
    allowed_ip_hash_key_id,
    lifecycle_state,
    dns_authority_reference,
    dns_state,
    dns_available_at,
    ephemeral,
    expires_at,
    created_at,
    updated_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(team_id),
    sqlc.arg(domain_id),
    sqlc.narg(membership_id),
    sqlc.arg(created_by_identity_id),
    sqlc.arg(idempotency_key),
    sqlc.arg(request_digest_ciphertext),
    sqlc.arg(request_digest_storage_key_id),
    sqlc.arg(canonical_hostname),
    sqlc.arg(namespace),
    sqlc.arg(target),
    sqlc.arg(public_url_scope),
    sqlc.arg(policy_revision),
    sqlc.arg(ip_policy),
    sqlc.narg(allowed_ip_policy_ciphertext),
    sqlc.narg(allowed_ip_policy_storage_key_id),
    sqlc.narg(allowed_ip_hashes),
    sqlc.narg(allowed_ip_hash_key_id),
    'enabled',
    sqlc.narg(dns_authority_reference),
    sqlc.arg(dns_state),
    CASE WHEN sqlc.arg(dns_state)::text = 'pending' THEN sqlc.arg(created_at)::timestamptz END,
    sqlc.arg(ephemeral),
    sqlc.narg(expires_at),
    sqlc.arg(created_at),
    sqlc.arg(created_at)
)
RETURNING *;

-- name: UpdatePublicURL :one
UPDATE control.public_urls
SET target = sqlc.arg(target),
    policy_revision = sqlc.arg(policy_revision),
    ip_policy = sqlc.arg(ip_policy),
    allowed_ip_policy_ciphertext = sqlc.narg(allowed_ip_policy_ciphertext),
    allowed_ip_policy_storage_key_id = sqlc.narg(allowed_ip_policy_storage_key_id),
    allowed_ip_hashes = sqlc.narg(allowed_ip_hashes),
    allowed_ip_hash_key_id = sqlc.narg(allowed_ip_hash_key_id),
    mutation_revision = mutation_revision + 1,
    updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(public_url_id)
  AND lifecycle_state = 'enabled'
  AND mutation_revision = sqlc.arg(expected_mutation_revision)
  AND mutation_revision < 9223372036854775807
RETURNING *;

-- name: RenewEphemeralPublicURLExpiry :one
UPDATE control.public_urls
SET expires_at = GREATEST(expires_at, sqlc.arg(expires_at))
WHERE id = sqlc.arg(public_url_id)
  AND ephemeral
  AND lifecycle_state <> 'deleted'
RETURNING expires_at;

-- name: LockExpiredEphemeralPublicURLs :many
SELECT *
FROM control.public_urls
WHERE ephemeral
  AND lifecycle_state <> 'deleted'
  AND expires_at <= sqlc.arg(now)
  AND NOT EXISTS (
      SELECT 1
      FROM control.publish_runs AS sessions
      WHERE sessions.public_url_id = control.public_urls.id
        AND sessions.closed_at IS NULL
        AND sessions.publisher_expires_at > sqlc.arg(now)
  )
ORDER BY expires_at, id
LIMIT sqlc.arg(batch_size)
FOR UPDATE SKIP LOCKED;

-- name: InsertPublicURLCreateAuditEvent :exec
INSERT INTO control.admin_audit_events (
    actor_identity_id,
    actor,
    request_id,
    operation,
    target_kind,
    target_id,
    occurred_at
) VALUES (
    sqlc.arg(actor_identity_id),
    sqlc.arg(actor_identity_id),
    sqlc.arg(request_id),
    'public_url.create',
    'public_url',
    sqlc.arg(public_url_id),
    sqlc.arg(occurred_at)
);

-- name: ListIdentityPublicURLs :many
SELECT r.*,
    COALESCE((
        SELECT s.id
        FROM control.publish_runs AS s
        WHERE s.public_url_id = r.id
          AND s.closed_at IS NULL
    ), '')::text AS open_publish_run_id
FROM control.public_urls AS r
WHERE r.team_id = sqlc.arg(team_id)
  AND r.lifecycle_state <> 'deleted'
  AND (sqlc.narg(cursor)::text IS NULL OR r.id > sqlc.narg(cursor))
  AND EXISTS (
      SELECT 1
      FROM control.team_memberships AS m
      WHERE m.team_id = r.team_id
        AND m.identity_id = sqlc.arg(identity_id)
        AND m.removed_at IS NULL
  )
ORDER BY r.id
LIMIT 101;

-- name: GetIdentityPublicURL :one
SELECT r.*,
    COALESCE((
        SELECT s.id
        FROM control.publish_runs AS s
        WHERE s.public_url_id = r.id
          AND s.closed_at IS NULL
    ), '')::text AS open_publish_run_id
FROM control.public_urls AS r
WHERE r.id = sqlc.arg(public_url_id)
  AND r.lifecycle_state <> 'deleted'
  AND EXISTS (
      SELECT 1
      FROM control.team_memberships AS m
      WHERE m.team_id = r.team_id
        AND m.identity_id = sqlc.arg(identity_id)
        AND m.removed_at IS NULL
  );

-- name: LockIdentityPublicURLForDelete :one
SELECT r.*, m.id AS actor_membership_id, m.role AS actor_role
FROM control.public_urls AS r
JOIN control.team_memberships AS m
  ON m.team_id = r.team_id
 AND m.identity_id = sqlc.arg(identity_id)
 AND m.removed_at IS NULL
WHERE r.id = sqlc.arg(public_url_id)
  AND r.lifecycle_state <> 'deleted'
FOR UPDATE OF r, m;

-- name: LockLocalPublicURLTeamForMutation :one
WITH guard AS MATERIALIZED (
    SELECT routes.team_id,
        pg_advisory_xact_lock(hashtextextended('tnl:local-team:' || routes.team_id, 0))
    FROM control.public_urls AS routes
    WHERE routes.id = sqlc.arg(public_url_id)
)
SELECT teams.id
FROM control.teams AS teams
JOIN guard ON guard.team_id = teams.id
WHERE teams.deleted_at IS NULL
FOR NO KEY UPDATE OF teams;

-- name: DeletePublicURL :execrows
UPDATE control.public_urls
SET lifecycle_state = 'deleted',
    ip_policy = 'allow_all',
    allowed_ip_policy_ciphertext = NULL,
    allowed_ip_policy_storage_key_id = NULL,
    allowed_ip_hashes = NULL,
    allowed_ip_hash_key_id = NULL,
    request_digest_ciphertext = NULL,
    request_digest_storage_key_id = NULL,
    dns_state = CASE
        WHEN dns_state NOT IN ('unmanaged', 'removed') THEN 'removing'
        ELSE dns_state
    END,
    dns_revision = CASE
        WHEN dns_state NOT IN ('unmanaged', 'removed') THEN dns_revision + 1
        ELSE dns_revision
    END,
    dns_work_owner = NULL,
    dns_work_expires_at = NULL,
    dns_available_at = CASE
        WHEN dns_state NOT IN ('unmanaged', 'removed') THEN sqlc.arg(deleted_at)
        ELSE dns_available_at
    END,
    dns_last_error = NULL,
    mutation_revision = mutation_revision + 1,
    suspended_at = NULL,
    deleted_at = sqlc.arg(deleted_at),
    updated_at = sqlc.arg(deleted_at)
WHERE id = sqlc.arg(public_url_id)
  AND lifecycle_state <> 'deleted'
  AND mutation_revision = sqlc.arg(expected_mutation_revision)
  AND mutation_revision < 9223372036854775807;

-- name: InsertPublicURLDeleteAuditEvent :exec
INSERT INTO control.admin_audit_events (
    actor_identity_id,
    actor,
    request_id,
    operation,
    target_kind,
    target_id,
    occurred_at
) VALUES (
    sqlc.arg(actor_identity_id),
    sqlc.arg(actor_identity_id),
    sqlc.arg(request_id),
    'public_url.delete',
    'public_url',
    sqlc.arg(public_url_id),
    sqlc.arg(occurred_at)
);

-- name: InsertPublicURLUpdateAuditEvent :exec
INSERT INTO control.admin_audit_events (
    actor_identity_id,
    actor,
    request_id,
    operation,
    target_kind,
    target_id,
    occurred_at
) VALUES (
    sqlc.arg(actor_identity_id),
    sqlc.arg(actor_identity_id),
    sqlc.arg(request_id),
    'public_url.update',
    'public_url',
    sqlc.arg(public_url_id),
    sqlc.arg(occurred_at)
);

-- name: InsertExpiredEphemeralPublicURLDeleteAuditEvent :exec
INSERT INTO control.admin_audit_events (
    actor,
    request_id,
    operation,
    target_kind,
    target_id,
    occurred_at
) VALUES (
    'system',
    sqlc.arg(request_id),
    'public_url.delete',
    'public_url',
    sqlc.arg(public_url_id),
    sqlc.arg(occurred_at)
);

-- name: ClosePublishRun :one
UPDATE control.publish_runs
SET state = sqlc.arg(state),
    closed_at = sqlc.arg(closed_at),
    close_reason = sqlc.arg(close_reason)
WHERE id = sqlc.arg(publish_run_id)
  AND closed_at IS NULL
RETURNING *;

-- name: ClosePublishRunConnections :exec
UPDATE control.publish_run_connection_slots
SET state = 'closed',
    closed_at = COALESCE(closed_at, sqlc.arg(closed_at))
WHERE publish_run_id = sqlc.arg(publish_run_id)
  AND state <> 'closed';
