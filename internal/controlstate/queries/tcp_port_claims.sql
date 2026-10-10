-- name: LockTCPPortPublicURL :one
SELECT id, canonical_hostname, ingress_pool_id, service_protocol, lifecycle_state, public_port
FROM control.public_urls
WHERE id = sqlc.arg(public_url_id)
FOR NO KEY UPDATE;

-- name: GetHeldTCPPortClaim :one
SELECT * FROM control.tcp_port_claims
WHERE public_url_id = sqlc.arg(public_url_id) AND state = 'held';

-- name: ChooseTCPPort :one
SELECT ports.port
FROM control.ingress_pool_ports AS ports
JOIN control.ingress_pools AS pools ON pools.id = ports.ingress_pool_id
WHERE ports.ingress_pool_id = sqlc.arg(ingress_pool_id)
  AND ports.enabled AND pools.state = 'enabled'
  AND NOT EXISTS (
      SELECT 1 FROM control.tcp_port_claims AS claims
      WHERE claims.ingress_pool_id = ports.ingress_pool_id AND claims.port = ports.port
        AND claims.state IN ('held', 'quarantined')
  )
  AND NOT EXISTS (
      SELECT 1 FROM control.tcp_port_claims AS historical
      WHERE historical.ingress_pool_id = ports.ingress_pool_id AND historical.port = ports.port
        AND historical.canonical_hostname = sqlc.arg(canonical_hostname)
  )
ORDER BY COALESCE(array_position(sqlc.arg(preferred_ports)::integer[], ports.port), 2147483647),
         md5(sqlc.arg(seed)::text || ports.port::text)
LIMIT 1;

-- name: InsertTCPPortClaim :one
INSERT INTO control.tcp_port_claims
    (id, public_url_id, ingress_pool_id, canonical_hostname, port, state, claimed_at)
VALUES (sqlc.arg(id), sqlc.arg(public_url_id), sqlc.arg(ingress_pool_id),
    sqlc.arg(canonical_hostname), sqlc.arg(port), 'held', sqlc.arg(claimed_at))
ON CONFLICT DO NOTHING RETURNING *;

-- name: SetPublicURLTCPPort :execrows
UPDATE control.public_urls SET public_port = sqlc.arg(port)
WHERE id = sqlc.arg(public_url_id) AND public_port IS NULL
  AND service_protocol IN ('postgres', 'mysql');

-- name: QuarantineTCPPortClaim :execrows
UPDATE control.tcp_port_claims SET state = 'quarantined',
    retired_at = sqlc.arg(retired_at), reusable_after = sqlc.arg(reusable_after)
WHERE public_url_id = sqlc.arg(public_url_id) AND state = 'held';

-- name: ReleaseQuarantinedTCPPortClaims :execrows
UPDATE control.tcp_port_claims AS claims SET state = 'released'
WHERE claims.id IN (
    SELECT queued.id FROM control.tcp_port_claims AS queued
    WHERE queued.state = 'quarantined' AND queued.reusable_after <= sqlc.arg(now)
    ORDER BY queued.reusable_after, queued.id
    LIMIT 100 FOR UPDATE SKIP LOCKED
);

-- name: ListTCPPortPoolCapacity :many
SELECT pools.id AS ingress_pool_id,
    COUNT(ports.id) FILTER (WHERE ports.enabled)::bigint AS configured_ports,
    COUNT(claims.id) FILTER (WHERE ports.enabled AND claims.state = 'held')::bigint AS claimed_ports,
    COUNT(claims.id) FILTER (WHERE ports.enabled AND claims.state = 'quarantined')::bigint AS quarantined_ports
FROM control.ingress_pools AS pools
LEFT JOIN control.ingress_pool_ports AS ports ON ports.ingress_pool_id = pools.id
LEFT JOIN control.tcp_port_claims AS claims ON claims.ingress_pool_id = pools.id
    AND claims.port = ports.port AND claims.state IN ('held', 'quarantined')
GROUP BY pools.id ORDER BY pools.id;
