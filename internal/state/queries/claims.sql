-- name: GetClaimRequest :one
SELECT sqlc.embed(hostname_claims), hostname_claim_requests.requested_label, hostname_claim_requests.requested_kind
FROM hostname_claim_requests
JOIN hostname_claims ON hostname_claims.id = hostname_claim_requests.claim_id
WHERE hostname_claim_requests.principal_id = sqlc.arg(principal_id)
    AND hostname_claim_requests.request_key = sqlc.arg(request_key);

-- name: GetClaimByHostname :one
SELECT hostname_claims.*
FROM hostname_claims
WHERE hostname = sqlc.arg(hostname);

-- name: CountActivePersistentClaims :one
SELECT COUNT(*)
FROM hostname_claims
WHERE principal_id = sqlc.arg(principal_id)
    AND kind IN ('persistent_managed', 'persistent_custom_domain')
    AND state = 'active';

-- name: CountFriendlyNameCapacityConsumers :one
SELECT COUNT(*)
FROM hostname_claims
WHERE kind IN ('persistent_managed', 'ephemeral');

-- name: InsertClaim :execrows
INSERT INTO hostname_claims (
    id,
    principal_id,
    hostname,
    irreversible,
	kind,
	state,
	source,
	activated_at,
    created_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(principal_id),
    sqlc.arg(hostname),
    0,
	'persistent_managed',
	'active',
	'custom',
	CAST(sqlc.arg(created_at) AS INTEGER),
    sqlc.arg(created_at)
)
ON CONFLICT (hostname) DO NOTHING;

-- name: InsertGeneratedPersistentClaim :execrows
INSERT INTO hostname_claims (
    id, principal_id, hostname, kind, state, source, created_at, activated_at, irreversible
) VALUES (
    sqlc.arg(id), sqlc.arg(principal_id), sqlc.arg(hostname),
    'persistent_managed', 'active', 'generated', sqlc.arg(created_at), sqlc.arg(created_at), 0
)
ON CONFLICT (hostname) DO NOTHING;

-- name: InsertEphemeralClaim :execrows
INSERT INTO hostname_claims (
    id, principal_id, hostname, kind, state, source, created_at, irreversible
) VALUES (
    sqlc.arg(id), sqlc.arg(principal_id), sqlc.arg(hostname),
    'ephemeral', 'held', 'generated', sqlc.arg(created_at), 0
)
ON CONFLICT (hostname) DO NOTHING;

-- name: ReactivatePersistentClaim :execrows
UPDATE hostname_claims
SET state = 'active', activated_at = CAST(sqlc.arg(activated_at) AS INTEGER), released_at = NULL
WHERE id = sqlc.arg(id)
    AND principal_id = sqlc.arg(principal_id)
    AND kind = 'persistent_managed'
    AND state = 'released_owned';

-- name: CountClaimRequests :one
SELECT COUNT(*)
FROM hostname_claim_requests
JOIN hostname_claims ON hostname_claims.id = hostname_claim_requests.claim_id
WHERE hostname_claim_requests.principal_id = sqlc.arg(principal_id)
    AND NOT (hostname_claims.kind = 'ephemeral' AND hostname_claims.state = 'burned');

-- name: InsertClaimRequest :exec
INSERT INTO hostname_claim_requests (
    principal_id,
    request_key,
    requested_label,
	requested_kind,
    claim_id,
    created_at
) VALUES (
    sqlc.arg(principal_id),
    sqlc.arg(request_key),
    sqlc.arg(requested_label),
	sqlc.arg(requested_kind),
    sqlc.arg(claim_id),
    sqlc.arg(created_at)
);

-- name: ListActiveClaimsPage :many
SELECT hostname_claims.*
FROM hostname_claims
WHERE principal_id = sqlc.arg(principal_id)
    AND (
        kind = 'persistent_managed' AND state IN ('active', 'released_owned')
        OR kind = 'persistent_custom_domain' AND state = 'active'
    )
    AND (CAST(sqlc.arg(cursor) AS TEXT) = '' OR id > CAST(sqlc.arg(cursor) AS TEXT))
ORDER BY id
LIMIT sqlc.arg(limit);

-- name: ListActiveRoutesForClaim :many
SELECT routes.id
FROM hostname_claims
LEFT JOIN routes ON routes.claim_id = hostname_claims.id
    AND routes.state = 'active'
WHERE hostname_claims.id = sqlc.arg(claim_id)
    AND hostname_claims.principal_id = sqlc.arg(principal_id)
    AND hostname_claims.kind IN ('persistent_managed', 'persistent_custom_domain')
    AND hostname_claims.state = 'active'
ORDER BY routes.id;

-- name: ReleasePersistentClaim :execrows
UPDATE hostname_claims
SET state = 'released_owned', released_at = CAST(sqlc.arg(released_at) AS INTEGER)
WHERE id = sqlc.arg(id)
    AND principal_id = sqlc.arg(principal_id)
    AND kind = 'persistent_managed'
    AND state = 'active';

-- name: ReleaseCustomDomainClaim :execrows
UPDATE hostname_claims
SET state = 'released', released_at = CAST(sqlc.arg(released_at) AS INTEGER)
WHERE id = sqlc.arg(id)
    AND principal_id = sqlc.arg(principal_id)
    AND kind = 'persistent_custom_domain'
    AND state = 'active';

-- name: GetClaimByID :one
SELECT hostname_claims.*
FROM hostname_claims
WHERE id = sqlc.arg(id);

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
