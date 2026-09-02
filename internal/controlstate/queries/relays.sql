-- Blocking service operations acquire a transaction advisory guard before any
-- service/lease row locks. Shared row readers alone can bypass a queued writer;
-- the advisory queue lets registration, placement and certificate writes progress.
-- SKIP LOCKED certificate preparation and bulk key rotation remain opportunistic
-- row-only writers: they never wait for a service row or acquire this guard after
-- holding one. Keep their nonblocking behavior rather than adding a lock upgrade.
-- name: RegisterRelay :one
WITH service_guard AS MATERIALIZED (
    SELECT pg_advisory_xact_lock(hashtextextended('tnl:relay-service:' || sqlc.arg(relay_service_id)::text, 0))
), relay_service AS (
    INSERT INTO control.relay_services (
        relay_service_id,
        relay_address,
        tls_server_name,
        created_at,
        updated_at
    ) SELECT
        sqlc.arg(relay_service_id),
        sqlc.arg(relay_address),
        sqlc.arg(tls_server_name),
        sqlc.arg(registered_at),
        sqlc.arg(registered_at)
    FROM service_guard
    WHERE true
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
    renewed_at = CASE
        WHEN control.relay_leases.relay_run_id = EXCLUDED.relay_run_id
         AND control.relay_leases.lease_expires_at > EXCLUDED.registered_at
         AND control.relay_leases.draining
            THEN control.relay_leases.renewed_at
        ELSE EXCLUDED.renewed_at
    END,
    lease_expires_at = CASE
        WHEN control.relay_leases.relay_run_id = EXCLUDED.relay_run_id
         AND control.relay_leases.lease_expires_at > EXCLUDED.registered_at
         AND control.relay_leases.draining
            THEN control.relay_leases.lease_expires_at
        ELSE EXCLUDED.lease_expires_at
    END
WHERE (control.relay_leases.relay_run_id = EXCLUDED.relay_run_id
    OR control.relay_leases.lease_expires_at <= EXCLUDED.registered_at)
  AND NOT (control.relay_leases.relay_run_id = EXCLUDED.relay_run_id
      AND control.relay_leases.draining
      AND control.relay_leases.lease_expires_at <= EXCLUDED.registered_at)
RETURNING *
)
SELECT relay_lease.*, relay_service.relay_address, relay_service.tls_server_name
FROM relay_lease
JOIN relay_service USING (relay_service_id);

-- name: RenewRelay :one
WITH renewed_lease AS (
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
  AND NOT leases.draining
RETURNING leases.*
), relay_lease AS (
SELECT renewed_lease.* FROM renewed_lease
UNION ALL
SELECT leases.*
FROM control.relay_leases AS leases
WHERE leases.relay_service_id = sqlc.arg(relay_service_id)
  AND leases.relay_id = sqlc.arg(relay_id)
  AND leases.relay_run_id = sqlc.arg(relay_run_id)
  AND leases.relay_lease_revision = sqlc.arg(relay_lease_revision)
  AND leases.lease_expires_at > sqlc.arg(renewed_at)
  AND leases.draining
  AND NOT EXISTS (SELECT FROM renewed_lease)
)
SELECT relay_lease.*, services.relay_address, services.tls_server_name
FROM relay_lease
JOIN control.relay_services AS services USING (relay_service_id);

-- name: BeginRelayDrain :one
WITH drained_lease AS (
UPDATE control.relay_leases AS leases
SET draining = true,
    drain_deadline = sqlc.arg(drain_deadline),
    renewed_at = sqlc.arg(renewed_at),
    lease_expires_at = sqlc.arg(drain_deadline)
WHERE leases.relay_service_id = sqlc.arg(relay_service_id)
  AND leases.relay_id = sqlc.arg(relay_id)
  AND leases.relay_run_id = sqlc.arg(relay_run_id)
  AND leases.relay_lease_revision = sqlc.arg(relay_lease_revision)
  AND leases.lease_expires_at > sqlc.arg(renewed_at)
  AND NOT leases.draining
RETURNING leases.*
), relay_lease AS (
SELECT drained_lease.* FROM drained_lease
UNION ALL
SELECT leases.*
FROM control.relay_leases AS leases
WHERE leases.relay_service_id = sqlc.arg(relay_service_id)
  AND leases.relay_id = sqlc.arg(relay_id)
  AND leases.relay_run_id = sqlc.arg(relay_run_id)
  AND leases.relay_lease_revision = sqlc.arg(relay_lease_revision)
  AND leases.lease_expires_at > sqlc.arg(renewed_at)
  AND leases.draining
  AND NOT EXISTS (SELECT FROM drained_lease)
)
SELECT relay_lease.*, services.relay_address, services.tls_server_name
FROM relay_lease
JOIN control.relay_services AS services USING (relay_service_id);

-- Claims and readiness read service configuration without changing it. Share
-- that guard across processes. Claims exclusively lock the selected lease's
-- non-key fields so capacity checks cannot race each other, renewal, or drain.
-- NO KEY UPDATE also permits readiness's KEY SHARE guard: becoming ready does
-- not consume another connection. Registration and placement take the service
-- exclusively before leases; keep that order here too.
-- name: GetRelayLeaseForClaim :one
WITH service_guard AS MATERIALIZED (
    SELECT relay_service_id,
        pg_advisory_xact_lock_shared(hashtextextended('tnl:relay-service:' || relay_service_id, 0))
    FROM control.relay_leases
    WHERE relay_id = sqlc.arg(relay_id)
), service AS MATERIALIZED (
    SELECT services.*
    FROM control.relay_services AS services
    JOIN service_guard USING (relay_service_id)
    FOR SHARE OF services
)
SELECT leases.*, services.relay_address, services.tls_server_name
FROM control.relay_leases AS leases
JOIN service AS services USING (relay_service_id)
WHERE leases.relay_id = sqlc.arg(relay_id)
FOR NO KEY UPDATE OF leases;

-- Readiness retains the service guard through routing publication so process
-- registration/replacement cannot change its identity. KEY SHARE protects the
-- lease's existence without serializing claims or other readiness publications.
-- Renewal/drain may overlap; readiness validates the lease it reads, and routing
-- projection reads independently exclude a lease that has since drained.
-- name: GetRelayLeaseForReady :one
WITH service_guard AS MATERIALIZED (
    SELECT relay_service_id,
        pg_advisory_xact_lock_shared(hashtextextended('tnl:relay-service:' || relay_service_id, 0))
    FROM control.relay_leases
    WHERE relay_id = sqlc.arg(relay_id)
), service AS MATERIALIZED (
    SELECT services.*
    FROM control.relay_services AS services
    JOIN service_guard USING (relay_service_id)
    FOR SHARE OF services
)
SELECT leases.*, services.relay_address, services.tls_server_name
FROM control.relay_leases AS leases
JOIN service AS services USING (relay_service_id)
WHERE leases.relay_id = sqlc.arg(relay_id)
FOR KEY SHARE OF leases;

-- name: CountRelayActiveConnections :one
SELECT count(*)
FROM control.route_session_connections
WHERE connected_relay_id = sqlc.arg(relay_id)
  AND connected_relay_run_id = sqlc.arg(relay_run_id)
  AND connected_relay_lease_revision = sqlc.arg(relay_lease_revision)
  AND state IN ('connected', 'ready', 'draining');

-- Acquire the reservation guard before service guards and rows, in one command.
-- Callers finish locking all services before locking leases or checking capacity.
-- name: LockRelayServicesForPlacement :many
WITH assignment_guard AS MATERIALIZED (
    SELECT pg_advisory_xact_lock(hashtextextended('tnl:relay-assignment-totals', 0))
), service_guards AS MATERIALIZED (
    SELECT relay_service_id,
        pg_advisory_xact_lock(hashtextextended('tnl:relay-service:' || relay_service_id, 0))
    FROM control.relay_services CROSS JOIN assignment_guard
    WHERE enabled
    ORDER BY relay_service_id
)
SELECT services.relay_service_id
FROM control.relay_services AS services
JOIN service_guards USING (relay_service_id)
WHERE services.enabled
ORDER BY services.relay_service_id
FOR UPDATE OF services;

-- name: LockEligibleRelayLeases :many
SELECT leases.*, services.relay_address, services.tls_server_name
FROM control.relay_leases AS leases
JOIN control.relay_services AS services USING (relay_service_id)
WHERE leases.lease_expires_at > sqlc.arg(now)
  AND leases.relay_service_id = ANY(sqlc.arg(relay_service_ids)::text[])
  AND NOT leases.draining
  AND services.enabled
  AND leases.protocol_version = sqlc.arg(protocol_version)
  AND leases.connection_capacity > 0
  AND leases.stream_capacity > 0
ORDER BY leases.relay_service_id, leases.relay_id
FOR UPDATE OF leases;

-- name: LockRelayServiceForCertificate :one
WITH service_guard AS MATERIALIZED (
    SELECT pg_advisory_xact_lock(hashtextextended('tnl:relay-service:' || sqlc.arg(relay_service_id)::text, 0))
)
SELECT services.relay_service_id
FROM control.relay_services AS services CROSS JOIN service_guard
WHERE services.relay_service_id = sqlc.arg(relay_service_id)
FOR UPDATE OF services;

-- Diagnostic/test oracle only; placement reads the trigger-maintained totals.
-- name: CountOpenRouteSessionAssignmentsByRelayService :many
SELECT connections.relay_service_id,
    count(*) AS assignment_count
FROM control.route_session_connections AS connections
JOIN control.route_sessions AS sessions ON sessions.id = connections.route_session_id
WHERE sessions.closed_at IS NULL
  AND connections.state IN ('assigned', 'connected', 'ready', 'draining')
GROUP BY connections.relay_service_id;

-- name: ListRelayServiceAssignmentTotals :many
SELECT relay_service_id, assignment_count
FROM control.relay_service_assignment_totals;

-- name: StoreRelayTransportCertificate :one
WITH service_guard AS MATERIALIZED (
    SELECT pg_advisory_xact_lock(hashtextextended('tnl:relay-service:' || sqlc.arg(relay_service_id)::text, 0))
)
UPDATE control.relay_services AS services
SET transport_certificate_pem = sqlc.arg(transport_certificate_pem),
    transport_private_key_ciphertext = sqlc.arg(transport_private_key_ciphertext),
    transport_private_key_storage_key_id = sqlc.arg(transport_private_key_storage_key_id),
    transport_certificate_serial = sqlc.arg(transport_certificate_serial),
    transport_certificate_expires_at = sqlc.arg(transport_certificate_expires_at),
    updated_at = GREATEST(updated_at, sqlc.arg(updated_at))
FROM service_guard
WHERE relay_service_id = sqlc.arg(relay_service_id)
  AND tls_server_name = sqlc.arg(tls_server_name)
  AND enabled
RETURNING services.*;

-- name: GetRelayTransportCertificate :one
SELECT services.*
FROM control.relay_services AS services
JOIN control.relay_leases AS leases USING (relay_service_id)
WHERE services.relay_service_id = sqlc.arg(relay_service_id)
  AND services.enabled
  AND leases.relay_id = sqlc.arg(relay_id)
  AND leases.relay_run_id = sqlc.arg(relay_run_id)
  AND leases.relay_lease_revision = sqlc.arg(relay_lease_revision)
  AND leases.lease_expires_at > sqlc.arg(now);

-- name: RotateRelayServicePrivateKey :exec
WITH service_guard AS MATERIALIZED (
    SELECT pg_advisory_xact_lock(hashtextextended('tnl:relay-service:' || sqlc.arg(relay_service_id)::text, 0))
)
UPDATE control.relay_services
SET transport_private_key_ciphertext = sqlc.arg(transport_private_key_ciphertext),
    transport_private_key_storage_key_id = sqlc.arg(transport_private_key_storage_key_id),
    updated_at = GREATEST(updated_at, sqlc.arg(updated_at))
FROM service_guard
WHERE relay_service_id = sqlc.arg(relay_service_id)
  AND transport_private_key_storage_key_id = sqlc.arg(previous_key_id)
  AND transport_private_key_ciphertext = sqlc.arg(previous_ciphertext);
