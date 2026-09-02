-- name: GetHostnameRequest :one
SELECT sqlc.embed(hostnames), hostname_requests.requested_label, hostname_requests.requested_kind
FROM hostname_requests
JOIN hostnames ON hostnames.id = hostname_requests.hostname_id
WHERE hostname_requests.identity_id = CAST(sqlc.arg(identity_id) AS TEXT)
    AND hostname_requests.request_key = sqlc.arg(request_key);

-- name: GetHostnameByHostname :one
SELECT hostnames.*
FROM hostnames
WHERE hostname = sqlc.arg(hostname);

-- name: CountActivePersistentHostnames :one
SELECT COUNT(*)
FROM hostnames
WHERE identity_id = CAST(sqlc.arg(identity_id) AS TEXT)
    AND kind IN ('managed', 'custom_domain')
    AND status = 'active';

-- name: CountFriendlyNameCapacityConsumers :one
SELECT COUNT(*)
FROM hostnames
WHERE kind IN ('managed', 'temporary');

-- name: InsertHostname :execrows
INSERT INTO hostnames (
    id,
    identity_id,
    hostname,
	kind,
	status,
	source,
	activated_at,
    created_at
) VALUES (
    sqlc.arg(id),
    CAST(sqlc.arg(identity_id) AS TEXT),
    sqlc.arg(hostname),
	'managed',
	'active',
	'user',
	CAST(sqlc.arg(created_at) AS INTEGER),
    sqlc.arg(created_at)
)
ON CONFLICT (hostname) DO NOTHING;

-- name: InsertGeneratedManagedHostname :execrows
INSERT INTO hostnames (
    id, identity_id, hostname, kind, status, source, created_at, activated_at
) VALUES (
    sqlc.arg(id), CAST(sqlc.arg(identity_id) AS TEXT), sqlc.arg(hostname),
    'managed', 'active', 'generated', sqlc.arg(created_at), sqlc.arg(created_at)
)
ON CONFLICT (hostname) DO NOTHING;

-- name: InsertTemporaryHostname :execrows
INSERT INTO hostnames (
    id, identity_id, hostname, kind, status, source, created_at
) VALUES (
    sqlc.arg(id), CAST(sqlc.arg(identity_id) AS TEXT), sqlc.arg(hostname),
    'temporary', 'pending_route', 'generated', sqlc.arg(created_at)
)
ON CONFLICT (hostname) DO NOTHING;

-- name: ReactivateManagedHostname :execrows
UPDATE hostnames
SET status = 'active', activated_at = CAST(sqlc.arg(activated_at) AS INTEGER), deactivated_at = NULL
WHERE id = sqlc.arg(id)
    AND identity_id = CAST(sqlc.arg(identity_id) AS TEXT)
    AND kind = 'managed'
    AND status = 'inactive';

-- name: CountHostnameRequests :one
SELECT COUNT(*)
FROM hostname_requests
JOIN hostnames ON hostnames.id = hostname_requests.hostname_id
WHERE hostname_requests.identity_id = CAST(sqlc.arg(identity_id) AS TEXT)
    AND NOT (hostnames.kind = 'temporary' AND hostnames.status = 'retired');

-- name: InsertHostnameRequest :exec
INSERT INTO hostname_requests (
    identity_id,
    request_key,
    requested_label,
	requested_kind,
    hostname_id,
    created_at
) VALUES (
    CAST(sqlc.arg(identity_id) AS TEXT),
    sqlc.arg(request_key),
    sqlc.arg(requested_label),
	sqlc.arg(requested_kind),
    sqlc.arg(hostname_id),
    sqlc.arg(created_at)
);

-- name: ListHostnamesPage :many
SELECT hostnames.*
FROM hostnames
WHERE identity_id = CAST(sqlc.arg(identity_id) AS TEXT)
    AND (
        kind = 'managed' AND status IN ('active', 'inactive')
        OR kind = 'custom_domain' AND status = 'active'
    )
    AND (CAST(sqlc.arg(cursor) AS TEXT) = '' OR id > CAST(sqlc.arg(cursor) AS TEXT))
ORDER BY id
LIMIT sqlc.arg(limit);

-- name: ListActiveRoutesForHostname :many
SELECT routes.id
FROM hostnames
LEFT JOIN routes ON routes.hostname_id = hostnames.id
    AND routes.status = 'active'
WHERE hostnames.id = sqlc.arg(hostname_id)
    AND hostnames.identity_id = CAST(sqlc.arg(identity_id) AS TEXT)
    AND hostnames.kind IN ('managed', 'custom_domain')
    AND hostnames.status = 'active'
ORDER BY routes.id;

-- name: DeactivateManagedHostname :execrows
UPDATE hostnames
SET status = 'inactive', deactivated_at = CAST(sqlc.arg(deactivated_at) AS INTEGER)
WHERE id = sqlc.arg(id)
    AND identity_id = CAST(sqlc.arg(identity_id) AS TEXT)
    AND kind = 'managed'
    AND status = 'active';

-- name: MakeCustomDomainAvailable :execrows
UPDATE hostnames
SET status = 'available', identity_id = NULL,
    deactivated_at = CAST(sqlc.arg(deactivated_at) AS INTEGER)
WHERE id = sqlc.arg(id)
    AND identity_id = CAST(sqlc.arg(identity_id) AS TEXT)
    AND kind = 'custom_domain'
    AND status = 'active';

-- name: GetHostnameByID :one
SELECT hostnames.*
FROM hostnames
WHERE id = sqlc.arg(id);

-- name: DeleteHostnameRoutes :exec
UPDATE routes
SET status = 'deleted', deleted_at = CAST(sqlc.arg(deleted_at) AS INTEGER)
WHERE hostname_id = sqlc.arg(hostname_id)
    AND status = 'active';

-- name: RevokeHostnameRouteCredentials :exec
UPDATE route_credentials
SET revoked_at = COALESCE(revoked_at, CAST(sqlc.arg(revoked_at) AS INTEGER))
WHERE route_id IN (
    SELECT id
    FROM routes
    WHERE hostname_id = sqlc.arg(hostname_id)
);

-- name: ExpireHostnameRouteSessions :exec
UPDATE route_sessions
SET status = 'expired'
WHERE route_id IN (
    SELECT id
    FROM routes
    WHERE hostname_id = sqlc.arg(hostname_id)
)
    AND status != 'expired';
