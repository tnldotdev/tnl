-- name: GetPublisherConnectionForClaim :one
SELECT *
FROM control.route_session_connections
WHERE publisher_connection_id = sqlc.arg(publisher_connection_id)
FOR UPDATE;

-- name: ClaimPublisherConnection :one
UPDATE control.route_session_connections
SET connected_relay_id = sqlc.arg(relay_id),
    connected_relay_run_id = sqlc.arg(relay_run_id),
    connected_relay_lease_revision = sqlc.arg(relay_lease_revision),
    claim_id = sqlc.arg(claim_id),
    state = CASE WHEN state = 'ready' THEN state ELSE 'connected' END,
    connected_at = COALESCE(connected_at, sqlc.arg(connected_at)),
    disconnected_at = NULL,
    closed_at = NULL
WHERE publisher_connection_id = sqlc.arg(publisher_connection_id)
  AND route_session_id = sqlc.arg(route_session_id)
  AND route_id = sqlc.arg(route_id)
  AND route_version = sqlc.arg(route_version)
  AND connection_slot = sqlc.arg(connection_slot)
  AND connection_assignment_revision = sqlc.arg(connection_assignment_revision)
  AND relay_service_id = sqlc.arg(relay_service_id)
  AND (
      state = 'assigned'
      OR (
          state IN ('connected', 'ready')
          AND connected_relay_id = sqlc.arg(relay_id)
          AND connected_relay_run_id = sqlc.arg(relay_run_id)
          AND connected_relay_lease_revision = sqlc.arg(relay_lease_revision)
          AND claim_id = sqlc.arg(claim_id)
      )
  )
RETURNING *;

-- name: MarkPublisherConnectionReady :one
UPDATE control.route_session_connections
SET state = 'ready',
    ready_at = COALESCE(ready_at, sqlc.arg(ready_at)),
    disconnected_at = NULL,
    closed_at = NULL
WHERE publisher_connection_id = sqlc.arg(publisher_connection_id)
  AND route_session_id = sqlc.arg(route_session_id)
  AND route_id = sqlc.arg(route_id)
  AND route_version = sqlc.arg(route_version)
  AND connection_slot = sqlc.arg(connection_slot)
  AND connection_assignment_revision = sqlc.arg(connection_assignment_revision)
  AND relay_service_id = sqlc.arg(relay_service_id)
  AND connected_relay_id = sqlc.arg(relay_id)
  AND connected_relay_run_id = sqlc.arg(relay_run_id)
  AND connected_relay_lease_revision = sqlc.arg(relay_lease_revision)
  AND claim_id = sqlc.arg(claim_id)
  AND state IN ('connected', 'ready')
RETURNING *;

-- name: DisconnectPublisherConnection :one
UPDATE control.route_session_connections
SET state = 'closed',
    disconnected_at = sqlc.arg(disconnected_at),
    closed_at = sqlc.arg(disconnected_at)
WHERE publisher_connection_id = sqlc.arg(publisher_connection_id)
  AND route_session_id = sqlc.arg(route_session_id)
  AND route_id = sqlc.arg(route_id)
  AND route_version = sqlc.arg(route_version)
  AND connection_slot = sqlc.arg(connection_slot)
  AND connection_assignment_revision = sqlc.arg(connection_assignment_revision)
  AND relay_service_id = sqlc.arg(relay_service_id)
  AND connected_relay_id = sqlc.arg(relay_id)
  AND connected_relay_run_id = sqlc.arg(relay_run_id)
  AND connected_relay_lease_revision = sqlc.arg(relay_lease_revision)
  AND claim_id = sqlc.arg(claim_id)
  AND state IN ('connected', 'ready', 'draining')
RETURNING *;
