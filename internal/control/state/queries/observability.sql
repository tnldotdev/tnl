-- name: ServicePortPoolCapacity :many
WITH inventory AS (
    SELECT ingress_pool_id, sum(last_port - first_port + 1)::bigint AS configured
    FROM control.ingress_service_port_ranges
    GROUP BY ingress_pool_id
), claims AS (
    SELECT ingress_pool_id,
        count(*) FILTER (WHERE state = 'held')::bigint AS claimed,
        count(*) FILTER (WHERE state = 'quarantined')::bigint AS quarantined
    FROM control.managed_service_port_claims
    WHERE state <> 'released'
    GROUP BY ingress_pool_id
)
SELECT inventory.ingress_pool_id, inventory.configured,
    COALESCE(claims.claimed, 0)::bigint AS claimed,
    COALESCE(claims.quarantined, 0)::bigint AS quarantined,
    GREATEST(0, inventory.configured - COALESCE(claims.claimed, 0) - COALESCE(claims.quarantined, 0))::bigint AS available
FROM inventory LEFT JOIN claims USING (ingress_pool_id)
ORDER BY inventory.ingress_pool_id;
