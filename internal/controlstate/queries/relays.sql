-- name: RegisterRelay :one
WITH relay_service AS (
    INSERT INTO control.relay_services (
        relay_service_id,
        relay_address,
        tls_server_name,
        created_at,
        updated_at
    ) VALUES (
        sqlc.arg(relay_service_id),
        sqlc.arg(relay_address),
        sqlc.arg(tls_server_name),
        sqlc.arg(registered_at),
        sqlc.arg(registered_at)
    )
    ON CONFLICT (relay_service_id) DO UPDATE SET
        updated_at = EXCLUDED.updated_at
    WHERE control.relay_services.relay_address = EXCLUDED.relay_address
      AND control.relay_services.tls_server_name = EXCLUDED.tls_server_name
      AND control.relay_services.enabled
	RETURNING relay_service_id, relay_address, tls_server_name
), relay_lease AS (
INSERT INTO control.relay_leases (
    relay_id,
    relay_service_id,
    relay_run_id,
    relay_lease_revision,
    protocol_version,
    internal_relay_address,
    internal_networks,
    connection_capacity,
    stream_capacity,
    registered_at,
    renewed_at,
    lease_expires_at
)
SELECT
    sqlc.arg(relay_id),
    relay_service.relay_service_id,
    sqlc.arg(relay_run_id),
    1,
    sqlc.arg(protocol_version),
    sqlc.arg(internal_relay_address),
    sqlc.arg(internal_networks),
    sqlc.arg(connection_capacity),
    sqlc.arg(stream_capacity),
    sqlc.arg(registered_at),
    sqlc.arg(renewed_at),
    sqlc.arg(lease_expires_at)
FROM relay_service
ON CONFLICT (relay_id) DO UPDATE SET
    relay_service_id = EXCLUDED.relay_service_id,
    relay_run_id = EXCLUDED.relay_run_id,
    relay_lease_revision = CASE
        WHEN control.relay_leases.relay_run_id = EXCLUDED.relay_run_id
         AND control.relay_leases.lease_expires_at > EXCLUDED.registered_at
            THEN control.relay_leases.relay_lease_revision
        ELSE control.relay_leases.relay_lease_revision + 1
    END,
    protocol_version = EXCLUDED.protocol_version,
    internal_relay_address = EXCLUDED.internal_relay_address,
    internal_networks = EXCLUDED.internal_networks,
    connection_capacity = EXCLUDED.connection_capacity,
    stream_capacity = EXCLUDED.stream_capacity,
    reported_connections = CASE
        WHEN control.relay_leases.relay_run_id = EXCLUDED.relay_run_id
         AND control.relay_leases.lease_expires_at > EXCLUDED.registered_at
            THEN control.relay_leases.reported_connections
        ELSE 0
    END,
    reported_streams = CASE
        WHEN control.relay_leases.relay_run_id = EXCLUDED.relay_run_id
         AND control.relay_leases.lease_expires_at > EXCLUDED.registered_at
            THEN control.relay_leases.reported_streams
        ELSE 0
    END,
    draining = CASE
        WHEN control.relay_leases.relay_run_id = EXCLUDED.relay_run_id
         AND control.relay_leases.lease_expires_at > EXCLUDED.registered_at
            THEN control.relay_leases.draining
        ELSE false
    END,
    drain_deadline = CASE
        WHEN control.relay_leases.relay_run_id = EXCLUDED.relay_run_id
         AND control.relay_leases.lease_expires_at > EXCLUDED.registered_at
            THEN control.relay_leases.drain_deadline
        ELSE NULL
    END,
    registered_at = CASE
        WHEN control.relay_leases.relay_run_id = EXCLUDED.relay_run_id
         AND control.relay_leases.lease_expires_at > EXCLUDED.registered_at
            THEN control.relay_leases.registered_at
        ELSE EXCLUDED.registered_at
    END,
    renewed_at = EXCLUDED.renewed_at,
    lease_expires_at = EXCLUDED.lease_expires_at
WHERE control.relay_leases.relay_run_id = EXCLUDED.relay_run_id
   OR control.relay_leases.lease_expires_at <= EXCLUDED.registered_at
RETURNING *
)
SELECT relay_lease.*, relay_service.relay_address, relay_service.tls_server_name
FROM relay_lease
JOIN relay_service USING (relay_service_id);

-- name: RenewRelay :one
WITH relay_lease AS (
UPDATE control.relay_leases AS leases
SET reported_connections = sqlc.arg(reported_connections),
    reported_streams = sqlc.arg(reported_streams),
    renewed_at = sqlc.arg(renewed_at),
    lease_expires_at = sqlc.arg(lease_expires_at)
WHERE leases.relay_service_id = sqlc.arg(relay_service_id)
  AND leases.relay_id = sqlc.arg(relay_id)
  AND leases.relay_run_id = sqlc.arg(relay_run_id)
  AND leases.relay_lease_revision = sqlc.arg(relay_lease_revision)
  AND leases.lease_expires_at > sqlc.arg(renewed_at)
RETURNING leases.*
)
SELECT relay_lease.*, services.relay_address, services.tls_server_name
FROM relay_lease
JOIN control.relay_services AS services USING (relay_service_id);

-- name: BeginRelayDrain :one
WITH relay_lease AS (
UPDATE control.relay_leases AS leases
SET draining = true,
    drain_deadline = sqlc.arg(drain_deadline),
    renewed_at = sqlc.arg(renewed_at),
    lease_expires_at = GREATEST(leases.lease_expires_at, sqlc.arg(drain_deadline))
WHERE leases.relay_service_id = sqlc.arg(relay_service_id)
  AND leases.relay_id = sqlc.arg(relay_id)
  AND leases.relay_run_id = sqlc.arg(relay_run_id)
  AND leases.relay_lease_revision = sqlc.arg(relay_lease_revision)
  AND leases.lease_expires_at > sqlc.arg(renewed_at)
RETURNING leases.*
)
SELECT relay_lease.*, services.relay_address, services.tls_server_name
FROM relay_lease
JOIN control.relay_services AS services USING (relay_service_id);

-- name: GetRelayLeaseForClaim :one
SELECT leases.*, services.relay_address, services.tls_server_name
FROM control.relay_leases AS leases
JOIN control.relay_services AS services USING (relay_service_id)
WHERE leases.relay_id = sqlc.arg(relay_id)
FOR UPDATE OF leases, services;

-- name: CountRelayActiveConnections :one
SELECT count(*)
FROM control.route_session_connections
WHERE connected_relay_id = sqlc.arg(relay_id)
  AND connected_relay_run_id = sqlc.arg(relay_run_id)
  AND connected_relay_lease_revision = sqlc.arg(relay_lease_revision)
  AND state IN ('connected', 'ready', 'draining');

-- name: LockEligibleRelayLeases :many
SELECT leases.*, services.relay_address, services.tls_server_name
FROM control.relay_leases AS leases
JOIN control.relay_services AS services USING (relay_service_id)
WHERE leases.lease_expires_at > sqlc.arg(now)
  AND NOT leases.draining
  AND services.enabled
  AND leases.protocol_version = sqlc.arg(protocol_version)
  AND leases.connection_capacity > 0
  AND leases.stream_capacity > 0
ORDER BY leases.relay_service_id, leases.relay_id
FOR UPDATE OF leases, services;

-- name: CountOpenRouteSessionAssignmentsByRelayService :many
SELECT connections.relay_service_id,
    count(*) AS assignment_count
FROM control.route_session_connections AS connections
JOIN control.route_sessions AS sessions ON sessions.id = connections.route_session_id
WHERE sessions.closed_at IS NULL
  AND connections.state IN ('assigned', 'connected', 'ready', 'draining')
GROUP BY connections.relay_service_id;
