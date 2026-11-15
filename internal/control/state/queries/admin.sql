-- name: GetAdminRuntimeCounts :one
WITH live_services AS (
    SELECT id,guest_id,enabled FROM control.services
    WHERE deleted_at IS NULL AND (expires_at IS NULL OR expires_at>sqlc.arg(now))
), current_runs AS (
    SELECT run.state,run.healthy,run.certificate_expires_at
    FROM control.service_runs run
    JOIN live_services service ON service.id=run.service_id AND service.enabled
    WHERE run.state IN ('starting','ready') AND run.closed_at IS NULL
        AND run.publisher_expires_at>sqlc.arg(now)
        AND EXISTS(SELECT 1 FROM control.publisher_service_permission(
            run.publisher_identity_id,run.publisher_grant_id,run.service_id,sqlc.arg(now)) permission
            JOIN control.publisher_grants grant_record ON grant_record.id=run.publisher_grant_id
            JOIN control.publisher_identity_keys signing ON signing.id=run.publisher_key_id
                AND signing.publisher_identity_id=run.publisher_identity_id
                AND (grant_record.kind='service' OR signing.retired_at IS NULL))
        AND (service.guest_id IS NULL OR EXISTS(SELECT 1 FROM control.guest_trials guest
            WHERE guest.id=service.guest_id AND guest.active_service_run_id=run.id
                AND control.guest_serving_deadline(guest.id,sqlc.arg(now))>sqlc.arg(now)))
)
SELECT
    (SELECT count(*) FROM live_services WHERE enabled) AS enabled_services,
    (SELECT count(*) FROM live_services WHERE NOT enabled) AS suspended_services,
    (SELECT count(*) FROM current_runs WHERE state='starting') AS starting_service_runs,
    (SELECT count(*) FROM current_runs WHERE state='ready' AND healthy
        AND certificate_expires_at>sqlc.arg(now)) AS ready_service_runs,
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
ORDER BY operation;

-- name: LockMaintenanceControl :one
SELECT allowed FROM control.maintenance_controls
WHERE operation=sqlc.arg(operation)
FOR SHARE;

-- name: SetMaintenanceControl :one
UPDATE control.maintenance_controls
SET allowed = sqlc.arg(allowed),
    revision = revision + 1,
    updated_at = sqlc.arg(updated_at),
    updated_by = sqlc.arg(updated_by)
WHERE operation = sqlc.arg(control_name)
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
