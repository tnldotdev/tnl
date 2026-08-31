-- name: GetClaimRequest :one
SELECT sqlc.embed(hostname_claims), hostname_claim_requests.requested_label
FROM hostname_claim_requests
JOIN hostname_claims ON hostname_claims.id = hostname_claim_requests.claim_id
WHERE hostname_claim_requests.principal_id = sqlc.arg(principal_id)
    AND hostname_claim_requests.request_key = sqlc.arg(request_key);

-- name: GetClaimByHostname :one
SELECT hostname_claims.*
FROM hostname_claims
WHERE hostname = sqlc.arg(hostname);

-- name: CountActiveClaims :one
SELECT COUNT(*)
FROM hostname_claims
WHERE principal_id = sqlc.arg(principal_id)
    AND tombstoned_at IS NULL;

-- name: InsertClaim :execrows
INSERT INTO hostname_claims (
    id,
    principal_id,
    hostname,
    irreversible,
    created_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(principal_id),
    sqlc.arg(hostname),
    0,
    sqlc.arg(created_at)
)
ON CONFLICT (hostname) DO NOTHING;

-- name: CountClaimRequests :one
SELECT COUNT(*)
FROM hostname_claim_requests
WHERE principal_id = sqlc.arg(principal_id);

-- name: InsertClaimRequest :exec
INSERT INTO hostname_claim_requests (
    principal_id,
    request_key,
    requested_label,
    claim_id,
    created_at
) VALUES (
    sqlc.arg(principal_id),
    sqlc.arg(request_key),
    sqlc.arg(requested_label),
    sqlc.arg(claim_id),
    sqlc.arg(created_at)
);

-- name: ListActiveClaimsPage :many
SELECT hostname_claims.*
FROM hostname_claims
WHERE principal_id = sqlc.arg(principal_id)
    AND tombstoned_at IS NULL
    AND (CAST(sqlc.arg(cursor) AS TEXT) = '' OR id > CAST(sqlc.arg(cursor) AS TEXT))
ORDER BY id
LIMIT sqlc.arg(limit);

-- name: GetActiveRouteForClaim :one
SELECT routes.id
FROM hostname_claims
LEFT JOIN routes ON routes.claim_id = hostname_claims.id
    AND routes.state = 'active'
WHERE hostname_claims.id = sqlc.arg(claim_id)
    AND hostname_claims.principal_id = sqlc.arg(principal_id)
    AND hostname_claims.tombstoned_at IS NULL;

-- name: TombstoneClaim :execrows
UPDATE hostname_claims
SET tombstoned_at = CAST(sqlc.arg(tombstoned_at) AS INTEGER)
WHERE id = sqlc.arg(id)
    AND principal_id = sqlc.arg(principal_id)
    AND tombstoned_at IS NULL;

-- name: DeleteClaimRoutes :exec
UPDATE routes
SET state = 'deleted', deleted_at = CAST(sqlc.arg(deleted_at) AS INTEGER)
WHERE claim_id = sqlc.arg(claim_id)
    AND state = 'active';

-- name: RevokeClaimRouteCredentials :exec
UPDATE route_credentials
SET revoked_at = COALESCE(revoked_at, CAST(sqlc.arg(revoked_at) AS INTEGER))
WHERE route_id IN (
    SELECT id
    FROM routes
    WHERE claim_id = sqlc.arg(claim_id)
);

-- name: ExpireClaimRouteLeases :exec
UPDATE route_leases
SET status = 'expired'
WHERE route_id IN (
    SELECT id
    FROM routes
    WHERE claim_id = sqlc.arg(claim_id)
)
    AND status != 'expired';
