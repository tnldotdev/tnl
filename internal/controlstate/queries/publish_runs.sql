-- name: LockPublicURLForRun :one
-- publish run operations serialize with public URL mutations without changing
-- public URL identity. NO KEY UPDATE permits usage's KEY SHARE references;
-- overlapping usage pages could starve a stronger UPDATE heartbeat lock.
SELECT *
FROM control.public_urls
WHERE id = sqlc.arg(public_url_id)
FOR NO KEY UPDATE;

-- name: GetPublishRunByIdempotency :one
SELECT *
FROM control.publish_runs
WHERE public_url_id = sqlc.arg(public_url_id)
  AND idempotency_key = sqlc.arg(idempotency_key);

-- name: GetOpenPublishRun :one
SELECT *
FROM control.publish_runs
WHERE public_url_id = sqlc.arg(public_url_id)
  AND closed_at IS NULL;

-- lock public URLs before publish runs, as heartbeat and closure do. the
-- partial expiration index finds candidates; SKIP LOCKED leaves busy public
-- URLs to other controls and active publishers.
-- name: LockExpiredPublishRunPublicURLs :many
SELECT routes.*
FROM control.publish_runs AS sessions
JOIN control.public_urls AS routes ON routes.id = sessions.public_url_id
WHERE sessions.closed_at IS NULL
  AND (sessions.publisher_expires_at <= sqlc.arg(now) OR EXISTS (
      SELECT 1 FROM control.guest_public_urls AS guest_url
      JOIN control.guest_trials AS guest ON guest.id = guest_url.guest_id
      WHERE guest_url.public_url_id = routes.id AND (
          guest.expires_at <= sqlc.arg(now)
          OR guest.used_bytes >= 5242880
          OR guest.used_ready_ns >= 900000000000
          OR guest.active_ready_at IS NOT NULL AND guest.used_ready_ns +
              GREATEST(0, (EXTRACT(EPOCH FROM (sqlc.arg(now)::timestamptz - guest.active_ready_at)) * 1000000000)::bigint) >= 900000000000
      )
  ))
ORDER BY sessions.publisher_expires_at, sessions.id
LIMIT sqlc.arg(batch_size)
FOR NO KEY UPDATE OF routes SKIP LOCKED;

-- name: GetActivePublishRunMembership :one
SELECT m.id, m.role, t.policy_revision
FROM control.team_memberships AS m
JOIN control.teams AS t
  ON t.id = m.team_id
 AND t.deleted_at IS NULL
WHERE m.team_id = sqlc.arg(team_id)
  AND m.identity_id = sqlc.arg(identity_id)
  AND m.removed_at IS NULL
FOR SHARE OF m, t;

-- name: ListPublishRunConnections :many
SELECT *
FROM control.publish_run_connection_slots
WHERE publish_run_id = sqlc.arg(publish_run_id)
ORDER BY connection_slot;

-- name: LockPublishRunCreationControl :one
SELECT allowed
FROM control.maintenance_controls
WHERE control_name = 'publish_run_creation'
FOR SHARE;

-- name: InsertPublishRun :one
WITH version AS (
UPDATE control.public_urls
SET next_publish_run_number = next_publish_run_number + 1,
    mutation_revision = mutation_revision + 1,
    updated_at = sqlc.arg(created_at)
WHERE id = sqlc.arg(public_url_id)
  AND next_publish_run_number < 9223372036854775807
  AND mutation_revision = sqlc.arg(expected_mutation_revision)
  AND mutation_revision < 9223372036854775807
  AND lifecycle_state = 'enabled'
RETURNING (next_publish_run_number - 1)::bigint AS publish_run_number
)
INSERT INTO control.publish_runs (
    id,
    public_url_id,
    team_id,
    membership_id,
    acting_identity_id,
    publish_run_number,
    idempotency_key,
    request_digest_ciphertext,
    request_digest_storage_key_id,
    publish_run_token_id,
    publish_run_token_digest,
    policy_revision,
    certificate_cache_key,
    certificate_scope,
    certificate_identifiers,
    certificate_challenge_method,
    state,
    created_at,
    last_heartbeat_at,
    publisher_expires_at
) SELECT
    sqlc.arg(id),
    sqlc.arg(public_url_id),
    sqlc.arg(team_id),
    sqlc.narg(membership_id),
    sqlc.arg(acting_identity_id),
    version.publish_run_number,
    sqlc.arg(idempotency_key),
    sqlc.arg(request_digest_ciphertext),
    sqlc.arg(request_digest_storage_key_id),
    sqlc.arg(publish_run_token_id),
    sqlc.arg(publish_run_token_digest),
    sqlc.arg(policy_revision),
    sqlc.arg(certificate_cache_key),
    sqlc.arg(certificate_scope),
    sqlc.arg(certificate_identifiers),
    sqlc.arg(certificate_challenge_method),
    'starting',
    sqlc.arg(created_at),
    sqlc.arg(last_heartbeat_at),
    sqlc.arg(publisher_expires_at)
FROM version
RETURNING *;

-- name: InsertPublishRunConnections :many
INSERT INTO control.publish_run_connection_slots (
    publish_run_id,
    public_url_id,
    publish_run_number,
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
    sqlc.arg(publish_run_id),
    sqlc.arg(public_url_id),
    sqlc.arg(publish_run_number),
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

-- a failed ready connection can keep its existing service reservation. this
-- atomic ready -> assigned transition has zero counter delta and needs only the
-- caller's public URL/publish run locks, not placement's global/service/lease guards.
-- check failure and eligible service capacity in the statement snapshot. a
-- concurrent lease/configuration change may invalidate the returned assignment,
-- just as one immediately after commit can; claim checks the exact current lease
-- and process capacity under its exclusive lease guard. no capacity is added here.
-- closed or expired slots have no reservation and require guarded placement first.
-- name: ReplacePublishRunConnection :one
UPDATE control.publish_run_connection_slots AS connections
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
WHERE publish_run_id = sqlc.arg(publish_run_id)
  AND connection_slot = sqlc.arg(connection_slot)
  AND publisher_connection_id = sqlc.arg(previous_publisher_connection_id)
  AND connection_assignment_revision = sqlc.arg(previous_connection_assignment_revision)
  AND (
      state IN ('closed', 'expired')
      OR (
          state = 'ready' AND session_open
          AND connections.relay_service_id = sqlc.arg(relay_service_id)
          AND NOT EXISTS (
              SELECT 1 FROM control.relay_leases AS leases
              WHERE leases.relay_service_id = connections.relay_service_id
                AND leases.relay_id = connections.connected_relay_id
                AND leases.relay_run_id = connections.connected_relay_run_id
                AND leases.relay_lease_revision = connections.connected_relay_lease_revision
                AND leases.lease_expires_at > sqlc.arg(assigned_at)
                AND NOT leases.draining AND leases.protocol_version = 1
                AND leases.connection_capacity > 0 AND leases.stream_capacity > 0
          )
          AND EXISTS (
              SELECT services.relay_service_id
              FROM control.relay_services AS services
              JOIN control.relay_service_assignment_totals AS totals USING (relay_service_id)
              JOIN control.relay_leases AS leases USING (relay_service_id)
              WHERE services.relay_service_id = connections.relay_service_id
                AND services.enabled
                AND leases.lease_expires_at > sqlc.arg(assigned_at)
                AND NOT leases.draining AND leases.protocol_version = 1
                AND leases.connection_capacity > 0 AND leases.stream_capacity > 0
              GROUP BY services.relay_service_id, totals.assignment_count
              HAVING sum(leases.connection_capacity) >= totals.assignment_count
          )
      )
  )
RETURNING connections.*;

-- name: InsertPublishRunAuditEvent :exec
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
    'publish_run.create',
    'publish_run',
    sqlc.arg(publish_run_id),
    sqlc.arg(occurred_at)
);
