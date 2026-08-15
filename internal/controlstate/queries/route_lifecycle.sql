-- name: LockRouteSession :one
SELECT *
FROM control.route_sessions
WHERE id = sqlc.arg(route_session_id)
FOR UPDATE;

-- name: GetRouteSession :one
SELECT *
FROM control.route_sessions
WHERE id = sqlc.arg(route_session_id);

-- name: MarkRouteSessionCertificateInstalled :one
UPDATE control.route_sessions
SET certificate_installed_at = CASE
        WHEN certificate_issuance_id = sqlc.arg(issuance_id) THEN certificate_installed_at
        ELSE sqlc.arg(installed_at)
    END,
    certificate_issuance_id = sqlc.arg(issuance_id),
    certificate_not_after = sqlc.arg(not_after)
WHERE id = sqlc.arg(route_session_id)
  AND route_id = sqlc.arg(route_id)
  AND route_version = sqlc.arg(route_version)
  AND closed_at IS NULL
RETURNING *;

-- name: MarkRouteSessionReady :one
UPDATE control.route_sessions AS sessions
SET state = 'ready',
    ready_at = COALESCE(sessions.ready_at, sqlc.arg(ready_at))
WHERE sessions.id = sqlc.arg(route_session_id)
  AND sessions.route_id = sqlc.arg(route_id)
  AND sessions.route_version = sqlc.arg(route_version)
  AND sessions.closed_at IS NULL
  AND sessions.certificate_installed_at IS NOT NULL
  AND (
      SELECT count(*)
      FROM control.route_session_connections AS connections
      WHERE connections.route_session_id = sqlc.arg(route_session_id)
        AND connections.state = 'ready'
  ) = 2
RETURNING sessions.*;

-- name: HeartbeatRouteSession :one
UPDATE control.route_sessions
SET last_heartbeat_at = GREATEST(last_heartbeat_at, sqlc.arg(heartbeat_at)),
    publisher_expires_at = GREATEST(publisher_expires_at, sqlc.arg(expires_at))
WHERE id = sqlc.arg(route_session_id)
  AND route_id = sqlc.arg(route_id)
  AND route_version = sqlc.arg(route_version)
  AND closed_at IS NULL
  AND publisher_expires_at > sqlc.arg(heartbeat_at)
RETURNING *;

-- name: ListValidReadyPublisherConnections :many
SELECT connections.route_session_id,
    connections.route_id,
    connections.route_version,
    connections.connection_slot,
    connections.publisher_connection_id,
    connections.connection_assignment_revision,
    connections.relay_service_id,
    connections.connected_relay_id,
    connections.connected_relay_run_id,
    connections.connected_relay_lease_revision,
    relays.internal_relay_address,
    services.tls_server_name,
    relays.lease_expires_at
FROM control.route_session_connections AS connections
JOIN control.relay_leases AS relays
  ON relays.relay_service_id = connections.relay_service_id
 AND relays.relay_id = connections.connected_relay_id
 AND relays.relay_run_id = connections.connected_relay_run_id
 AND relays.relay_lease_revision = connections.connected_relay_lease_revision
JOIN control.relay_services AS services
  ON services.relay_service_id = connections.relay_service_id
WHERE connections.route_session_id = sqlc.arg(route_session_id)
  AND connections.state = 'ready'
  AND relays.lease_expires_at > sqlc.arg(now)
  AND NOT relays.draining
  AND relays.protocol_version = 1
  AND relays.connection_capacity > 0
  AND relays.stream_capacity > 0
  AND services.enabled
ORDER BY connections.connection_slot;

-- name: LockInvalidReadyPublisherConnections :many
SELECT connections.*
FROM control.route_session_connections AS connections
LEFT JOIN control.relay_leases AS relays
  ON relays.relay_service_id = connections.relay_service_id
 AND relays.relay_id = connections.connected_relay_id
 AND relays.relay_run_id = connections.connected_relay_run_id
 AND relays.relay_lease_revision = connections.connected_relay_lease_revision
LEFT JOIN control.relay_services AS services
  ON services.relay_service_id = connections.relay_service_id
WHERE connections.state = 'ready'
  AND (
      relays.relay_id IS NULL
      OR relays.lease_expires_at <= sqlc.arg(now)
      OR relays.draining
      OR NOT services.enabled
  )
ORDER BY connections.route_session_id, connections.connection_slot
FOR UPDATE OF connections SKIP LOCKED;

-- name: ExpirePublisherConnection :one
UPDATE control.route_session_connections
SET state = 'expired',
    disconnected_at = COALESCE(disconnected_at, sqlc.arg(expired_at)),
    closed_at = COALESCE(closed_at, sqlc.arg(expired_at))
WHERE publisher_connection_id = sqlc.arg(publisher_connection_id)
  AND route_session_id = sqlc.arg(route_session_id)
  AND connection_assignment_revision = sqlc.arg(connection_assignment_revision)
  AND state IN ('assigned', 'connected', 'ready', 'draining')
RETURNING *;

-- name: OpenRouteRecoveryEpisode :exec
INSERT INTO control.route_recovery_episodes (
    route_id,
    route_version,
    state,
    opened_at
) VALUES (
    sqlc.arg(route_id),
    sqlc.arg(route_version),
    'open',
    sqlc.arg(opened_at)
)
ON CONFLICT (route_id, route_version) WHERE state = 'open' DO NOTHING;

-- name: GetOpenRouteRecoveryEpisode :one
SELECT *
FROM control.route_recovery_episodes
WHERE route_id = sqlc.arg(route_id)
  AND route_version = sqlc.arg(route_version)
  AND state = 'open';

-- name: CancelOpenRouteRecoveryEpisode :one
UPDATE control.route_recovery_episodes
SET state = 'canceled',
    canceled_at = sqlc.arg(canceled_at)
WHERE route_id = sqlc.arg(route_id)
  AND route_version = sqlc.arg(route_version)
  AND state = 'open'
RETURNING *;

-- name: LockRouteRecoveryEpisode :one
SELECT *
FROM control.route_recovery_episodes
WHERE recovery_episode_id = sqlc.arg(recovery_episode_id)
FOR UPDATE;

-- name: ObserveRouteRecoveryEpisode :one
UPDATE control.route_recovery_episodes
SET state = 'observed',
    observed_at = sqlc.arg(observed_at),
    observed_seconds = sqlc.arg(observed_seconds)
WHERE recovery_episode_id = sqlc.arg(recovery_episode_id)
  AND route_id = sqlc.arg(route_id)
  AND route_version = sqlc.arg(route_version)
  AND state = 'open'
RETURNING *;

-- name: UpdateRouteRecoveryHistogram :one
UPDATE control.route_recovery_histogram
SET observation_count = observation_count + 1,
    observation_sum_seconds = observation_sum_seconds + sqlc.arg(observed_seconds),
    bucket_le_0_25 = bucket_le_0_25 + CASE WHEN sqlc.arg(observed_seconds) <= 0.25 THEN 1 ELSE 0 END,
    bucket_le_0_5 = bucket_le_0_5 + CASE WHEN sqlc.arg(observed_seconds) <= 0.5 THEN 1 ELSE 0 END,
    bucket_le_1 = bucket_le_1 + CASE WHEN sqlc.arg(observed_seconds) <= 1 THEN 1 ELSE 0 END,
    bucket_le_2 = bucket_le_2 + CASE WHEN sqlc.arg(observed_seconds) <= 2 THEN 1 ELSE 0 END,
    bucket_le_5 = bucket_le_5 + CASE WHEN sqlc.arg(observed_seconds) <= 5 THEN 1 ELSE 0 END,
    bucket_le_10 = bucket_le_10 + CASE WHEN sqlc.arg(observed_seconds) <= 10 THEN 1 ELSE 0 END,
    bucket_le_20 = bucket_le_20 + CASE WHEN sqlc.arg(observed_seconds) <= 20 THEN 1 ELSE 0 END,
    bucket_le_30 = bucket_le_30 + CASE WHEN sqlc.arg(observed_seconds) <= 30 THEN 1 ELSE 0 END,
    bucket_le_45 = bucket_le_45 + CASE WHEN sqlc.arg(observed_seconds) <= 45 THEN 1 ELSE 0 END,
    bucket_le_60 = bucket_le_60 + CASE WHEN sqlc.arg(observed_seconds) <= 60 THEN 1 ELSE 0 END,
    bucket_le_120 = bucket_le_120 + CASE WHEN sqlc.arg(observed_seconds) <= 120 THEN 1 ELSE 0 END,
    updated_at = sqlc.arg(updated_at)
WHERE singleton = true
RETURNING *;
