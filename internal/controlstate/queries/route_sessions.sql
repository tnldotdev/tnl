-- name: LockRouteForSession :one
SELECT *
FROM control.routes
WHERE id = sqlc.arg(route_id)
FOR UPDATE;

-- name: GetRouteSessionByIdempotency :one
SELECT *
FROM control.route_sessions
WHERE route_id = sqlc.arg(route_id)
  AND idempotency_key = sqlc.arg(idempotency_key);

-- name: GetOpenRouteSession :one
SELECT *
FROM control.route_sessions
WHERE route_id = sqlc.arg(route_id)
  AND closed_at IS NULL;

-- name: GetActiveRouteSessionMembership :one
SELECT m.id, m.role, t.policy_revision
FROM control.team_memberships AS m
JOIN control.teams AS t
  ON t.id = m.team_id
 AND t.deleted_at IS NULL
WHERE m.team_id = sqlc.arg(team_id)
  AND m.identity_id = sqlc.arg(identity_id)
  AND m.removed_at IS NULL
FOR SHARE OF m, t;

-- name: ListRouteSessionConnections :many
SELECT *
FROM control.route_session_connections
WHERE route_session_id = sqlc.arg(route_session_id)
ORDER BY connection_slot;

-- name: LockRouteSessionCreationControl :one
SELECT allowed
FROM control.maintenance_controls
WHERE control_name = 'route_session_creation'
FOR SHARE;

-- name: InsertRouteSession :one
WITH version AS (
UPDATE control.routes
SET next_route_version = next_route_version + 1,
    mutation_revision = mutation_revision + 1,
    updated_at = sqlc.arg(created_at)
WHERE id = sqlc.arg(route_id)
  AND next_route_version < 9223372036854775807
  AND mutation_revision = sqlc.arg(expected_mutation_revision)
  AND mutation_revision < 9223372036854775807
  AND lifecycle_state = 'enabled'
RETURNING (next_route_version - 1)::bigint AS route_version
)
INSERT INTO control.route_sessions (
    id,
    route_id,
    team_id,
    membership_id,
    acting_identity_id,
    route_version,
    idempotency_key,
    request_digest,
    session_token_id,
    session_token_digest,
    policy_revision,
    certificate_cache_key,
    certificate_scope,
    certificate_identifiers,
    certificate_challenge,
    state,
    created_at,
    last_heartbeat_at,
    publisher_expires_at
) SELECT
    sqlc.arg(id),
    sqlc.arg(route_id),
    sqlc.arg(team_id),
    sqlc.narg(membership_id),
    sqlc.arg(acting_identity_id),
    version.route_version,
    sqlc.arg(idempotency_key),
    sqlc.arg(request_digest),
    sqlc.arg(session_token_id),
    sqlc.arg(session_token_digest),
    sqlc.arg(policy_revision),
    sqlc.arg(certificate_cache_key),
    sqlc.arg(certificate_scope),
    sqlc.arg(certificate_identifiers),
    sqlc.arg(certificate_challenge),
    'starting',
    sqlc.arg(created_at),
    sqlc.arg(last_heartbeat_at),
    sqlc.arg(publisher_expires_at)
FROM version
RETURNING *;

-- name: InsertRouteSessionConnections :many
INSERT INTO control.route_session_connections (
    route_session_id,
    route_id,
    route_version,
    connection_slot,
    publisher_connection_id,
    connection_assignment_revision,
    relay_service_id,
    relay_address,
    tls_server_name,
    publisher_connection_credential_digest,
    publisher_connection_credential_expires_at,
    state,
    assigned_at
) SELECT
    sqlc.arg(route_session_id),
    sqlc.arg(route_id),
    sqlc.arg(route_version),
    slots.connection_slot::smallint,
    (sqlc.arg(publisher_connection_ids)::text[])[slots.connection_slot + 1],
    1,
    (sqlc.arg(relay_service_ids)::text[])[slots.connection_slot + 1],
    (sqlc.arg(relay_addresses)::text[])[slots.connection_slot + 1],
    (sqlc.arg(tls_server_names)::text[])[slots.connection_slot + 1],
    (sqlc.arg(credential_digests)::bytea[])[slots.connection_slot + 1],
    sqlc.arg(publisher_connection_credential_expires_at),
    'assigned',
    sqlc.arg(assigned_at)
FROM generate_series(0, 1) AS slots(connection_slot)
RETURNING *;

-- name: ReplaceRouteSessionConnection :one
UPDATE control.route_session_connections
SET publisher_connection_id = sqlc.arg(new_publisher_connection_id),
    connection_assignment_revision = sqlc.arg(new_connection_assignment_revision),
    relay_service_id = sqlc.arg(relay_service_id),
    relay_address = sqlc.arg(relay_address),
    tls_server_name = sqlc.arg(tls_server_name),
    publisher_connection_credential_digest = sqlc.arg(publisher_connection_credential_digest),
    publisher_connection_credential_expires_at = sqlc.arg(publisher_connection_credential_expires_at),
    connected_relay_id = NULL,
    connected_relay_run_id = NULL,
    connected_relay_lease_revision = NULL,
    claim_id = NULL,
    state = 'assigned',
    assigned_at = sqlc.arg(assigned_at),
    connected_at = NULL,
    ready_at = NULL,
    disconnected_at = NULL,
    closed_at = NULL
WHERE route_session_id = sqlc.arg(route_session_id)
  AND connection_slot = sqlc.arg(connection_slot)
  AND publisher_connection_id = sqlc.arg(previous_publisher_connection_id)
  AND connection_assignment_revision = sqlc.arg(previous_connection_assignment_revision)
  AND state IN ('closed', 'expired')
RETURNING *;

-- name: InsertRouteSessionAuditEvent :exec
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
    sqlc.arg(actor),
    sqlc.arg(request_id),
    'route_session.create',
    'route_session',
    sqlc.arg(route_session_id),
    sqlc.arg(occurred_at)
);
