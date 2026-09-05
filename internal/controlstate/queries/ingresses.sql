-- name: RegisterIngress :one
INSERT INTO control.ingress_leases (
    ingress_id,
    ingress_run_id,
    ingress_lease_revision,
    protocol_version,
    connection_capacity,
    registered_at,
    renewed_at,
    lease_expires_at
) VALUES (
    sqlc.arg(ingress_id),
    sqlc.arg(ingress_run_id),
    1,
    sqlc.arg(protocol_version),
    sqlc.arg(connection_capacity),
    sqlc.arg(registered_at),
    sqlc.arg(renewed_at),
    sqlc.arg(lease_expires_at)
)
ON CONFLICT (ingress_id) DO UPDATE SET
    ingress_run_id = EXCLUDED.ingress_run_id,
    ingress_lease_revision = CASE
        WHEN control.ingress_leases.ingress_run_id = EXCLUDED.ingress_run_id
         AND control.ingress_leases.lease_expires_at > EXCLUDED.registered_at
            THEN control.ingress_leases.ingress_lease_revision
        ELSE control.ingress_leases.ingress_lease_revision + 1
    END,
    protocol_version = EXCLUDED.protocol_version,
    connection_capacity = EXCLUDED.connection_capacity,
    reported_connections = CASE
        WHEN control.ingress_leases.ingress_run_id = EXCLUDED.ingress_run_id
         AND control.ingress_leases.lease_expires_at > EXCLUDED.registered_at
            THEN control.ingress_leases.reported_connections
        ELSE 0
    END,
    routing_table_revision = CASE
        WHEN control.ingress_leases.ingress_run_id = EXCLUDED.ingress_run_id
         AND control.ingress_leases.lease_expires_at > EXCLUDED.registered_at
            THEN control.ingress_leases.routing_table_revision
        ELSE 0
    END,
    draining = CASE
        WHEN control.ingress_leases.ingress_run_id = EXCLUDED.ingress_run_id
         AND control.ingress_leases.lease_expires_at > EXCLUDED.registered_at
            THEN control.ingress_leases.draining
        ELSE false
    END,
    drain_deadline = CASE
        WHEN control.ingress_leases.ingress_run_id = EXCLUDED.ingress_run_id
         AND control.ingress_leases.lease_expires_at > EXCLUDED.registered_at
            THEN control.ingress_leases.drain_deadline
        ELSE NULL
    END,
    registered_at = CASE
        WHEN control.ingress_leases.ingress_run_id = EXCLUDED.ingress_run_id
         AND control.ingress_leases.lease_expires_at > EXCLUDED.registered_at
            THEN control.ingress_leases.registered_at
        ELSE EXCLUDED.registered_at
    END,
    renewed_at = EXCLUDED.renewed_at,
    lease_expires_at = EXCLUDED.lease_expires_at
WHERE control.ingress_leases.ingress_run_id = EXCLUDED.ingress_run_id
   OR control.ingress_leases.lease_expires_at <= EXCLUDED.registered_at
RETURNING *;

-- name: RenewIngress :one
UPDATE control.ingress_leases
SET reported_connections = sqlc.arg(reported_connections),
    routing_table_revision = sqlc.arg(routing_table_revision),
    renewed_at = sqlc.arg(renewed_at),
    lease_expires_at = sqlc.arg(lease_expires_at)
WHERE ingress_id = sqlc.arg(ingress_id)
  AND ingress_run_id = sqlc.arg(ingress_run_id)
  AND ingress_lease_revision = sqlc.arg(ingress_lease_revision)
  AND lease_expires_at > sqlc.arg(renewed_at)
RETURNING *;

-- name: BeginIngressDrain :one
UPDATE control.ingress_leases
SET draining = true,
    drain_deadline = sqlc.arg(drain_deadline),
    renewed_at = sqlc.arg(renewed_at),
    lease_expires_at = GREATEST(lease_expires_at, sqlc.arg(drain_deadline))
WHERE ingress_id = sqlc.arg(ingress_id)
  AND ingress_run_id = sqlc.arg(ingress_run_id)
  AND ingress_lease_revision = sqlc.arg(ingress_lease_revision)
  AND lease_expires_at > sqlc.arg(renewed_at)
RETURNING *;

-- name: LockIngressLease :one
SELECT *
FROM control.ingress_leases
WHERE ingress_id = sqlc.arg(ingress_id)
  AND ingress_run_id = sqlc.arg(ingress_run_id)
  AND ingress_lease_revision = sqlc.arg(ingress_lease_revision)
  AND lease_expires_at > sqlc.arg(now)
FOR UPDATE;

-- name: GetIngressLease :one
SELECT *
FROM control.ingress_leases
WHERE ingress_id = sqlc.arg(ingress_id)
  AND ingress_run_id = sqlc.arg(ingress_run_id)
  AND ingress_lease_revision = sqlc.arg(ingress_lease_revision)
  AND lease_expires_at > sqlc.arg(now);
