-- name: GetIngressPool :one
SELECT * FROM control.ingress_pools WHERE id = sqlc.arg(id);

-- name: LockIngressPoolForProvision :one
SELECT * FROM control.ingress_pools WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: EnableIngressPool :one
UPDATE control.ingress_pools SET ipv4_address = sqlc.narg(ipv4_address)::inet,
    ipv6_address = sqlc.narg(ipv6_address)::inet,
    state = 'enabled', updated_at = GREATEST(updated_at, sqlc.arg(updated_at))
WHERE id = sqlc.arg(id) AND state = 'disabled'
RETURNING *;

-- name: EnableIngressPoolPorts :execrows
INSERT INTO control.ingress_pool_ports (ingress_pool_id, port, enabled)
SELECT sqlc.arg(ingress_pool_id), listed.port, true
FROM unnest(sqlc.arg(ports)::integer[]) AS listed(port)
ON CONFLICT (ingress_pool_id, port) DO UPDATE SET enabled = true;
