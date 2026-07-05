-- name: LockRouteCreator :one
SELECT id
FROM control.identities
WHERE id = sqlc.arg(identity_id)
  AND disabled_at IS NULL
-- Serialize creators without blocking session and audit foreign-key checks.
FOR NO KEY UPDATE;

-- name: GetRouteByCreatorIdempotency :one
SELECT r.*,
    COALESCE((
        SELECT s.id
        FROM control.route_sessions AS s
        WHERE s.route_id = r.id
          AND s.closed_at IS NULL
    ), '')::text AS attached_session_id
FROM control.routes AS r
WHERE r.created_by_identity_id = sqlc.arg(identity_id)
  AND r.idempotency_key = sqlc.arg(idempotency_key);

-- name: LockRouteCreationControl :one
SELECT enabled
FROM control.maintenance_controls
WHERE control_name = 'route_creation'
FOR UPDATE;

-- name: GetRouteCreationContext :one
SELECT
    t.kind AS team_kind,
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

-- name: ListTeamMemberNamespaceLabels :many
SELECT m.managed_label, s.member_slug
FROM control.team_memberships AS m
JOIN control.member_slug_reservations AS s ON s.id = m.slug_reservation_id
WHERE m.team_id = sqlc.arg(team_id)
  AND m.removed_at IS NULL;

-- name: InsertRoute :one
INSERT INTO control.routes (
    id,
    team_id,
    domain_id,
    membership_id,
    created_by_identity_id,
    idempotency_key,
    request_digest,
    canonical_hostname,
    target,
    route_scope,
    policy_revision,
    ip_policy,
    allowed_ip_prefixes,
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
    sqlc.arg(request_digest),
    sqlc.arg(canonical_hostname),
    sqlc.arg(target),
    sqlc.arg(route_scope),
    sqlc.arg(policy_revision),
    sqlc.arg(ip_policy),
    sqlc.arg(allowed_ip_prefixes),
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

-- name: UpdateRoute :one
UPDATE control.routes
SET target = sqlc.arg(target),
    policy_revision = sqlc.arg(policy_revision),
    ip_policy = sqlc.arg(ip_policy),
    allowed_ip_prefixes = sqlc.arg(allowed_ip_prefixes),
    mutation_revision = mutation_revision + 1,
    updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(route_id)
  AND lifecycle_state = 'enabled'
  AND mutation_revision = sqlc.arg(expected_mutation_revision)
  AND mutation_revision < 9223372036854775807
RETURNING *;

-- name: RenewEphemeralRouteExpiry :one
UPDATE control.routes
SET expires_at = GREATEST(expires_at, sqlc.arg(expires_at))
WHERE id = sqlc.arg(route_id)
  AND ephemeral
  AND lifecycle_state <> 'deleted'
RETURNING expires_at;

-- name: LockExpiredEphemeralRoutes :many
SELECT *
FROM control.routes
WHERE ephemeral
  AND lifecycle_state <> 'deleted'
  AND expires_at <= sqlc.arg(now)
  AND NOT EXISTS (
      SELECT 1
      FROM control.route_sessions AS sessions
      WHERE sessions.route_id = control.routes.id
        AND sessions.closed_at IS NULL
        AND sessions.publisher_expires_at > sqlc.arg(now)
  )
ORDER BY expires_at, id
LIMIT sqlc.arg(batch_size)
FOR UPDATE SKIP LOCKED;

-- name: InsertRouteCreateAuditEvent :exec
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
    'route.create',
    'route',
    sqlc.arg(route_id),
    sqlc.arg(occurred_at)
);

-- name: ListIdentityRoutes :many
SELECT r.*,
    COALESCE((
        SELECT s.id
        FROM control.route_sessions AS s
        WHERE s.route_id = r.id
          AND s.closed_at IS NULL
    ), '')::text AS attached_session_id
FROM control.routes AS r
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

-- name: GetIdentityRoute :one
SELECT r.*,
    COALESCE((
        SELECT s.id
        FROM control.route_sessions AS s
        WHERE s.route_id = r.id
          AND s.closed_at IS NULL
    ), '')::text AS attached_session_id
FROM control.routes AS r
WHERE r.id = sqlc.arg(route_id)
  AND r.lifecycle_state <> 'deleted'
  AND EXISTS (
      SELECT 1
      FROM control.team_memberships AS m
      WHERE m.team_id = r.team_id
        AND m.identity_id = sqlc.arg(identity_id)
        AND m.removed_at IS NULL
  );

-- name: LockIdentityRouteForDelete :one
SELECT r.*, m.id AS actor_membership_id, m.role AS actor_role
FROM control.routes AS r
JOIN control.team_memberships AS m
  ON m.team_id = r.team_id
 AND m.identity_id = sqlc.arg(identity_id)
 AND m.removed_at IS NULL
WHERE r.id = sqlc.arg(route_id)
  AND r.lifecycle_state <> 'deleted'
FOR UPDATE OF r, m;

-- name: LockLocalRouteTeamForMutation :one
SELECT teams.id
FROM control.teams AS teams
WHERE teams.id = (SELECT routes.team_id FROM control.routes AS routes WHERE routes.id = sqlc.arg(route_id))
  AND teams.deleted_at IS NULL
FOR NO KEY UPDATE;

-- name: DeleteRoute :execrows
UPDATE control.routes
SET lifecycle_state = 'deleted',
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
WHERE id = sqlc.arg(route_id)
  AND lifecycle_state <> 'deleted'
  AND mutation_revision = sqlc.arg(expected_mutation_revision)
  AND mutation_revision < 9223372036854775807;

-- name: InsertRouteDeleteAuditEvent :exec
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
    'route.delete',
    'route',
    sqlc.arg(route_id),
    sqlc.arg(occurred_at)
);

-- name: InsertRouteUpdateAuditEvent :exec
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
    'route.update',
    'route',
    sqlc.arg(route_id),
    sqlc.arg(occurred_at)
);

-- name: InsertExpiredEphemeralRouteDeleteAuditEvent :exec
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
    'route.delete',
    'route',
    sqlc.arg(route_id),
    sqlc.arg(occurred_at)
);

-- name: CloseRouteSession :one
UPDATE control.route_sessions
SET state = sqlc.arg(state),
    closed_at = sqlc.arg(closed_at),
    close_reason = sqlc.arg(close_reason)
WHERE id = sqlc.arg(route_session_id)
  AND closed_at IS NULL
RETURNING *;

-- name: CloseRouteSessionConnections :exec
UPDATE control.route_session_connections
SET state = 'closed',
    closed_at = COALESCE(closed_at, sqlc.arg(closed_at))
WHERE route_session_id = sqlc.arg(route_session_id)
  AND state <> 'closed';
