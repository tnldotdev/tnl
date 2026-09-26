-- name: GetAdminRuntimeCounts :one
SELECT
    (SELECT count(*) FROM control.public_urls AS routes WHERE routes.lifecycle_state = 'enabled') AS enabled_public_urls,
    (SELECT count(*) FROM control.public_urls AS routes WHERE routes.lifecycle_state = 'suspended') AS suspended_public_urls,
    (SELECT count(*) FROM control.publish_runs AS sessions
        WHERE sessions.state = 'starting' AND sessions.closed_at IS NULL AND sessions.publisher_expires_at > sqlc.arg(now)) AS starting_publish_runs,
    (SELECT count(*) FROM control.publish_runs AS sessions
        WHERE sessions.state = 'ready' AND sessions.closed_at IS NULL AND sessions.publisher_expires_at > sqlc.arg(now)) AS ready_publish_runs,
    (SELECT count(*) FROM control.ingress_leases AS ingresses WHERE ingresses.lease_expires_at > sqlc.arg(now)) AS ingress_leases,
    (SELECT count(*) FROM control.relay_leases AS relays WHERE relays.lease_expires_at > sqlc.arg(now)) AS relay_leases;

-- name: ListAdminRelayLeases :many
SELECT leases.*, services.relay_address, services.tls_server_name
FROM control.relay_leases AS leases
JOIN control.relay_services AS services USING (relay_service_id)
WHERE leases.lease_expires_at > sqlc.arg(now)
  AND (sqlc.narg(cursor)::text IS NULL OR leases.relay_id > sqlc.narg(cursor))
ORDER BY leases.relay_id
LIMIT sqlc.arg(page_limit);

-- name: BeginAdminRelayDrain :one
WITH relay_lease AS (
    UPDATE control.relay_leases AS leases
    SET draining = true,
        drain_deadline = sqlc.arg(drain_deadline),
        renewed_at = sqlc.arg(drained_at),
        lease_expires_at = sqlc.arg(drain_deadline)
    WHERE leases.relay_id = sqlc.arg(relay_id)
      AND leases.relay_run_id = sqlc.arg(relay_run_id)
      AND leases.relay_lease_revision = sqlc.arg(relay_lease_revision)
      AND leases.lease_expires_at > sqlc.arg(drained_at)
      AND NOT leases.draining
    RETURNING leases.*
)
SELECT relay_lease.*, services.relay_address, services.tls_server_name
FROM relay_lease
JOIN control.relay_services AS services USING (relay_service_id);

-- name: ListMaintenanceControls :many
SELECT *
FROM control.maintenance_controls
ORDER BY control_name;

-- name: SetMaintenanceControl :one
UPDATE control.maintenance_controls
SET allowed = sqlc.arg(allowed),
    revision = revision + 1,
    updated_at = sqlc.arg(updated_at),
    updated_by = sqlc.arg(updated_by)
WHERE control_name = sqlc.arg(control_name)
RETURNING *;

-- name: InsertAdminAuditEvent :exec
INSERT INTO control.admin_audit_events (
    actor_identity_id,
    actor,
    request_id,
    operation,
    target_kind,
    target_id,
    details,
    occurred_at
) VALUES (
    sqlc.arg(actor_identity_id),
    sqlc.arg(actor),
    sqlc.arg(request_id),
    sqlc.arg(operation),
    sqlc.arg(target_kind),
    sqlc.arg(target_id),
    sqlc.narg(details),
    sqlc.arg(occurred_at)
);
