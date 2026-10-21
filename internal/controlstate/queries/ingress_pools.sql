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
