-- name: GetAuthorizingRouteClaim :one
SELECT id, principal_id, hostname, kind, state, route_binding
FROM hostname_claims
WHERE principal_id = sqlc.arg(principal_id)
    AND state IN ('held', 'active')
    AND kind IN ('persistent_managed', 'persistent_custom_domain', 'ephemeral')
    AND (
        hostname = sqlc.arg(hostname)
        OR kind != 'ephemeral' AND sqlc.arg(hostname) LIKE '%.' || hostname
    )
ORDER BY length(hostname) DESC
LIMIT 1;

-- name: GetActiveRouteByHostname :one
SELECT routes.*
FROM routes
WHERE hostname = sqlc.arg(hostname) AND state = 'active';

-- name: BindEphemeralClaim :execrows
UPDATE hostname_claims
SET state = 'active', activated_at = CAST(sqlc.arg(activated_at) AS INTEGER), route_binding = CAST(sqlc.arg(route_id) AS TEXT)
WHERE id = sqlc.arg(claim_id)
    AND principal_id = sqlc.arg(principal_id)
    AND kind = 'ephemeral'
    AND state = 'held'
    AND route_binding IS NULL;

-- name: RotateRouteCredential :execrows
UPDATE route_credentials
SET
    id = sqlc.arg(credential_id),
    secret_hash = sqlc.arg(secret_hash),
    created_at = sqlc.arg(created_at),
    revoked_at = NULL
WHERE route_id = sqlc.arg(route_id);

-- name: ExpireRouteLeases :exec
UPDATE route_leases
SET status = 'expired'
WHERE route_id = sqlc.arg(route_id) AND status != 'expired';

-- name: ReplaceRoute :exec
UPDATE routes
SET
    display_target = sqlc.arg(display_target),
    generation = sqlc.arg(generation)
WHERE id = sqlc.arg(route_id);

-- name: InsertRouteLease :exec
INSERT INTO route_leases (
    id,
    route_id,
    generation,
    status,
    credential_id,
    secret_hash,
    boot_epoch,
    created_at,
    last_heartbeat,
    expires_at
) VALUES (
    sqlc.arg(lease_id),
    sqlc.arg(route_id),
    sqlc.arg(generation),
    'pending',
    sqlc.arg(credential_id),
    sqlc.arg(secret_hash),
    sqlc.arg(boot_epoch),
    sqlc.arg(created_at),
    sqlc.arg(created_at),
    sqlc.arg(expires_at)
);

-- name: InsertRoute :exec
INSERT INTO routes (
    id,
    claim_id,
    principal_id,
    hostname,
    display_target,
    state,
    generation,
    created_at
) VALUES (
    sqlc.arg(route_id),
    sqlc.arg(claim_id),
    sqlc.arg(principal_id),
    sqlc.arg(hostname),
    sqlc.arg(display_target),
    'active',
    1,
    sqlc.arg(created_at)
);

-- name: InsertRouteCredential :exec
INSERT INTO route_credentials (
    id,
    route_id,
    secret_hash,
    created_at
) VALUES (
    sqlc.arg(credential_id),
    sqlc.arg(route_id),
    sqlc.arg(secret_hash),
    sqlc.arg(created_at)
);

-- name: InsertInitialRouteLease :exec
INSERT INTO route_leases (
    id,
    route_id,
    generation,
    status,
    credential_id,
    secret_hash,
    boot_epoch,
    created_at,
    last_heartbeat,
    expires_at
) VALUES (
    sqlc.arg(lease_id),
    sqlc.arg(route_id),
    1,
    'pending',
    sqlc.arg(credential_id),
    sqlc.arg(secret_hash),
    sqlc.arg(boot_epoch),
    sqlc.arg(created_at),
    sqlc.arg(created_at),
    sqlc.arg(expires_at)
);

-- name: AdvanceRouteGeneration :exec
UPDATE routes
SET generation = sqlc.arg(generation)
WHERE id = sqlc.arg(route_id);

-- name: GetRouteCredential :one
SELECT
    sqlc.embed(routes),
    route_credentials.secret_hash,
    route_credentials.revoked_at
FROM routes
JOIN route_credentials ON route_credentials.route_id = routes.id
WHERE routes.id = sqlc.arg(route_id)
    AND route_credentials.id = sqlc.arg(credential_id);

-- name: CountActiveRoutesByPrincipal :one
SELECT COUNT(*)
FROM routes
WHERE id = sqlc.arg(route_id)
    AND principal_id = sqlc.arg(principal_id)
    AND state = 'active';

-- name: GetActiveRouteIDByHostname :one
SELECT id
FROM routes
WHERE principal_id = sqlc.arg(principal_id)
    AND hostname = sqlc.arg(hostname)
    AND state = 'active';

-- name: GetRouteLeaseForAuthentication :one
SELECT route_leases.*
FROM route_leases
JOIN routes ON routes.id = route_leases.route_id
WHERE route_leases.route_id = sqlc.arg(route_id)
    AND route_leases.generation = sqlc.arg(generation)
    AND route_leases.credential_id = sqlc.arg(credential_id)
    AND routes.state = 'active'
    AND routes.generation = route_leases.generation;

-- name: GetKnownRouteLeaseCredentialMarker :one
SELECT 1 AS known_credential
FROM route_leases
WHERE credential_id = sqlc.arg(credential_id);

-- name: RegisterRouteLeaseTransport :execrows
UPDATE route_leases
SET
    server_public_key = sqlc.arg(server_public_key),
    relay_profile = sqlc.arg(relay_profile),
    status = 'starting'
WHERE id = sqlc.arg(lease_id)
    AND route_id = sqlc.arg(route_id)
    AND generation = sqlc.arg(generation)
    AND status IN ('pending', 'starting');

-- name: ReadyRouteLease :execrows
UPDATE route_leases
SET status = 'ready'
WHERE id = sqlc.arg(lease_id)
    AND route_id = sqlc.arg(route_id)
    AND generation = sqlc.arg(generation)
    AND status = 'starting';

-- name: GetRouteLeaseStatus :one
SELECT status
FROM route_leases
WHERE id = sqlc.arg(lease_id)
    AND route_id = sqlc.arg(route_id)
    AND generation = sqlc.arg(generation);

-- name: HeartbeatRouteLease :execrows
UPDATE route_leases
SET
    last_heartbeat = sqlc.arg(last_heartbeat),
    expires_at = sqlc.arg(expires_at)
WHERE id = sqlc.arg(lease_id)
    AND route_id = sqlc.arg(route_id)
    AND generation = sqlc.arg(generation)
    AND status != 'expired';

-- name: InvalidateOtherBootRouteLeases :exec
UPDATE route_leases
SET status = 'expired'
WHERE boot_epoch != sqlc.arg(boot_epoch) AND status != 'expired';

-- name: ListOtherBootRouteLeases :many
SELECT route_id, generation
FROM route_leases
WHERE boot_epoch != sqlc.arg(boot_epoch) AND status != 'expired'
ORDER BY route_id, generation;

-- name: ExpireRouteLease :execrows
UPDATE route_leases
SET status = 'expired'
WHERE route_id = sqlc.arg(route_id)
    AND generation = sqlc.arg(generation)
    AND status != 'expired';

-- name: ListActiveRoutes :many
SELECT routes.*
FROM routes
WHERE principal_id = sqlc.arg(principal_id) AND state = 'active'
ORDER BY created_at, id;

-- name: DeleteActiveRoute :execrows
UPDATE routes
SET
    state = 'deleted',
    deleted_at = CAST(sqlc.arg(deleted_at) AS INTEGER)
WHERE id = sqlc.arg(route_id)
    AND principal_id = sqlc.arg(principal_id)
    AND state = 'active';

-- name: BurnEphemeralClaimByRoute :exec
UPDATE hostname_claims
SET state = 'burned', released_at = CAST(sqlc.arg(released_at) AS INTEGER), route_binding = NULL, reason = 'route ended'
WHERE route_binding = CAST(sqlc.arg(route_id) AS TEXT)
    AND kind = 'ephemeral'
    AND state IN ('held', 'active');

-- name: RevokeRouteCredential :exec
UPDATE route_credentials
SET revoked_at = COALESCE(revoked_at, CAST(sqlc.arg(revoked_at) AS INTEGER))
WHERE route_id = sqlc.arg(route_id);

-- name: GetRouteGeneration :one
SELECT generation
FROM routes
WHERE id = sqlc.arg(route_id);

-- name: ListActiveClaimRouteGenerations :many
SELECT id, generation
FROM routes
WHERE claim_id = sqlc.arg(claim_id) AND state = 'active'
ORDER BY id;

-- name: ListAbandonedEphemeralRoutes :many
SELECT hostname_claims.id AS claim_id, routes.id AS route_id
FROM hostname_claims
JOIN routes ON routes.claim_id = hostname_claims.id
WHERE hostname_claims.kind = 'ephemeral'
    AND hostname_claims.state = 'active'
    AND routes.state = 'active'
    AND NOT EXISTS (
        SELECT 1
        FROM route_leases
        WHERE route_leases.route_id = routes.id
            AND route_leases.expires_at > sqlc.arg(expired_before)
    )
ORDER BY routes.id;

-- name: BurnAbandonedEphemeralHolds :exec
UPDATE hostname_claims
SET state = 'burned', released_at = CAST(sqlc.arg(released_at) AS INTEGER), reason = 'abandoned hold'
WHERE kind = 'ephemeral'
    AND state = 'held'
    AND created_at <= sqlc.arg(created_before);
