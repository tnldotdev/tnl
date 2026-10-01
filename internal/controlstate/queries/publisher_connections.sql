-- name: GetPublisherConnectionForClaim :one
SELECT *
FROM control.publish_run_connections
WHERE publisher_connection_id = sqlc.arg(publisher_connection_id)
FOR UPDATE;

-- require the exact publish run, assignment revision, and relay service. only
-- the same process and claim ID may repeat a connected or ready claim.
-- name: ClaimPublisherConnection :one
UPDATE control.publish_run_connections
SET connected_relay_id = sqlc.arg(relay_id),
    connected_relay_run_id = sqlc.arg(relay_run_id),
    connected_relay_lease_revision = sqlc.arg(relay_lease_revision),
    claim_id = sqlc.arg(claim_id),
    state = CASE WHEN state = 'ready' THEN state ELSE 'connected' END,
    connected_at = COALESCE(connected_at, sqlc.arg(connected_at)),
    disconnected_at = NULL,
    closed_at = NULL
WHERE publisher_connection_id = sqlc.arg(publisher_connection_id)
  AND publish_run_id = sqlc.arg(publish_run_id)
  AND public_url_id = sqlc.arg(public_url_id)
  AND publish_run_number = sqlc.arg(publish_run_number)
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

-- ready is idempotent for the exact claim; a replaced assignment cannot revive.
-- name: MarkPublisherConnectionReady :one
UPDATE control.publish_run_connections
SET state = 'ready',
    ready_at = COALESCE(ready_at, sqlc.arg(ready_at)),
    disconnected_at = NULL,
    closed_at = NULL
WHERE publisher_connection_id = sqlc.arg(publisher_connection_id)
  AND publish_run_id = sqlc.arg(publish_run_id)
  AND public_url_id = sqlc.arg(public_url_id)
  AND publish_run_number = sqlc.arg(publish_run_number)
  AND connection_slot = sqlc.arg(connection_slot)
  AND connection_assignment_revision = sqlc.arg(connection_assignment_revision)
  AND relay_service_id = sqlc.arg(relay_service_id)
  AND connected_relay_id = sqlc.arg(relay_id)
  AND connected_relay_run_id = sqlc.arg(relay_run_id)
  AND connected_relay_lease_revision = sqlc.arg(relay_lease_revision)
  AND claim_id = sqlc.arg(claim_id)
  AND state IN ('connected', 'ready')
RETURNING *;

-- close only the exact claim so a late disconnect cannot close its replacement.
-- name: DisconnectPublisherConnection :one
UPDATE control.publish_run_connections
SET state = 'closed',
    disconnected_at = sqlc.arg(disconnected_at),
    closed_at = sqlc.arg(disconnected_at)
WHERE publisher_connection_id = sqlc.arg(publisher_connection_id)
  AND publish_run_id = sqlc.arg(publish_run_id)
  AND public_url_id = sqlc.arg(public_url_id)
  AND publish_run_number = sqlc.arg(publish_run_number)
  AND connection_slot = sqlc.arg(connection_slot)
  AND connection_assignment_revision = sqlc.arg(connection_assignment_revision)
  AND relay_service_id = sqlc.arg(relay_service_id)
  AND connected_relay_id = sqlc.arg(relay_id)
  AND connected_relay_run_id = sqlc.arg(relay_run_id)
  AND connected_relay_lease_revision = sqlc.arg(relay_lease_revision)
  AND claim_id = sqlc.arg(claim_id)
  AND state IN ('connected', 'ready', 'draining')
RETURNING *;
