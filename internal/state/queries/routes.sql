-- name: GetAuthorizingRouteHostname :one
SELECT id, identity_id, hostname, kind, status
FROM hostnames
WHERE identity_id = CAST(sqlc.arg(identity_id) AS TEXT)
    AND status IN ('pending_route', 'active')
    AND kind IN ('managed', 'custom_domain', 'temporary')
    AND (
        hostname = sqlc.arg(hostname)
        OR kind != 'temporary' AND sqlc.arg(hostname) LIKE '%.' || hostname
    )
ORDER BY length(hostname) DESC
LIMIT 1;

-- name: GetActiveRouteByHostname :one
SELECT routes.*
FROM routes
WHERE hostname = sqlc.arg(hostname) AND status = 'active';

-- name: ActivateTemporaryHostname :execrows
UPDATE hostnames
SET status = 'active', activated_at = CAST(sqlc.arg(activated_at) AS INTEGER)
WHERE id = sqlc.arg(hostname_id)
    AND identity_id = CAST(sqlc.arg(identity_id) AS TEXT)
    AND kind = 'temporary'
    AND status = 'pending_route';

-- name: RotateRouteCredential :execrows
UPDATE route_credentials
SET
    id = sqlc.arg(credential_id),
    secret_hash = sqlc.arg(secret_hash),
    created_at = sqlc.arg(created_at),
    revoked_at = NULL
WHERE route_id = sqlc.arg(route_id);

-- name: ExpireRouteSessions :exec
UPDATE route_sessions
SET status = 'expired'
WHERE route_id = sqlc.arg(route_id) AND status != 'expired';

-- name: ReplaceRoute :exec
UPDATE routes
SET
    local_target = sqlc.arg(local_target),
    version = sqlc.arg(version)
WHERE id = sqlc.arg(route_id);

-- name: InsertRouteSession :exec
INSERT INTO route_sessions (
    id,
    route_id,
    version,
    status,
    token_id,
    secret_hash,
    server_instance_id,
    created_at,
    last_heartbeat_at,
    expires_at
) VALUES (
    sqlc.arg(session_id),
    sqlc.arg(route_id),
    sqlc.arg(version),
    'pending',
    sqlc.arg(token_id),
    sqlc.arg(secret_hash),
    sqlc.arg(server_instance_id),
    sqlc.arg(created_at),
    sqlc.arg(created_at),
    sqlc.arg(expires_at)
);

-- name: InsertRoute :exec
INSERT INTO routes (
    id,
    hostname_id,
    identity_id,
    hostname,
    local_target,
    status,
    version,
    created_at
) VALUES (
    sqlc.arg(route_id),
    sqlc.arg(hostname_id),
    CAST(sqlc.arg(identity_id) AS TEXT),
    sqlc.arg(hostname),
    sqlc.arg(local_target),
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

-- name: InsertInitialRouteSession :exec
INSERT INTO route_sessions (
    id,
    route_id,
    version,
    status,
    token_id,
    secret_hash,
    server_instance_id,
    created_at,
    last_heartbeat_at,
    expires_at
) VALUES (
    sqlc.arg(session_id),
    sqlc.arg(route_id),
    1,
    'pending',
    sqlc.arg(token_id),
    sqlc.arg(secret_hash),
    sqlc.arg(server_instance_id),
    sqlc.arg(created_at),
    sqlc.arg(created_at),
    sqlc.arg(expires_at)
);

-- name: AdvanceRouteVersion :exec
UPDATE routes
SET version = sqlc.arg(version)
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

-- name: CountActiveRoutesByIdentity :one
SELECT COUNT(*)
FROM routes
WHERE id = sqlc.arg(route_id)
    AND identity_id = CAST(sqlc.arg(identity_id) AS TEXT)
    AND status = 'active';

-- name: GetActiveRouteIDByHostname :one
SELECT id
FROM routes
WHERE identity_id = CAST(sqlc.arg(identity_id) AS TEXT)
    AND hostname = sqlc.arg(hostname)
    AND status = 'active';

-- name: GetRouteSessionForAuthentication :one
SELECT route_sessions.*
FROM route_sessions
JOIN routes ON routes.id = route_sessions.route_id
WHERE route_sessions.route_id = sqlc.arg(route_id)
    AND route_sessions.version = sqlc.arg(version)
    AND route_sessions.token_id = sqlc.arg(token_id)
    AND routes.status = 'active'
    AND routes.version = route_sessions.version;

-- name: GetKnownRouteSessionTokenMarker :one
SELECT 1 AS known_credential
FROM route_sessions
WHERE token_id = sqlc.arg(token_id);

-- name: RegisterRouteSessionTransport :execrows
UPDATE route_sessions
SET
    publisher_public_key = sqlc.arg(publisher_public_key),
    relay_region = sqlc.arg(relay_region),
    status = 'starting'
WHERE id = sqlc.arg(session_id)
    AND route_id = sqlc.arg(route_id)
    AND version = sqlc.arg(version)
    AND status IN ('pending', 'starting');

-- name: ReadyRouteSession :execrows
UPDATE route_sessions
SET status = 'ready'
WHERE id = sqlc.arg(session_id)
    AND route_id = sqlc.arg(route_id)
    AND version = sqlc.arg(version)
    AND status = 'starting';

-- name: GetRouteSessionStatus :one
SELECT status
FROM route_sessions
WHERE id = sqlc.arg(session_id)
    AND route_id = sqlc.arg(route_id)
    AND version = sqlc.arg(version);

-- name: HeartbeatRouteSession :execrows
UPDATE route_sessions
SET
    last_heartbeat_at = sqlc.arg(last_heartbeat_at),
    expires_at = sqlc.arg(expires_at)
WHERE id = sqlc.arg(session_id)
    AND route_id = sqlc.arg(route_id)
    AND version = sqlc.arg(version)
    AND status != 'expired';

-- name: InvalidateOtherServerInstanceRouteSessions :exec
UPDATE route_sessions
SET status = 'expired'
WHERE server_instance_id != sqlc.arg(server_instance_id) AND status != 'expired';

-- name: ListOtherServerInstanceRouteSessions :many
SELECT route_id, version
FROM route_sessions
WHERE server_instance_id != sqlc.arg(server_instance_id) AND status != 'expired'
ORDER BY route_id, version;

-- name: ExpireRouteSession :execrows
UPDATE route_sessions
SET status = 'expired'
WHERE route_id = sqlc.arg(route_id)
    AND version = sqlc.arg(version)
    AND status != 'expired';

-- name: ListActiveRoutes :many
SELECT routes.*
FROM routes
WHERE identity_id = CAST(sqlc.arg(identity_id) AS TEXT) AND status = 'active'
ORDER BY created_at, id;

-- name: DeleteActiveRoute :execrows
UPDATE routes
SET
    status = 'deleted',
    deleted_at = CAST(sqlc.arg(deleted_at) AS INTEGER)
WHERE id = sqlc.arg(route_id)
    AND identity_id = CAST(sqlc.arg(identity_id) AS TEXT)
    AND status = 'active';

-- name: RetireTemporaryHostnameByRoute :exec
UPDATE hostnames
SET status = 'retired', deactivated_at = CAST(sqlc.arg(deactivated_at) AS INTEGER)
WHERE hostnames.id = (SELECT routes.hostname_id FROM routes WHERE routes.id = sqlc.arg(route_id))
    AND kind = 'temporary'
    AND status IN ('pending_route', 'active');

-- name: RevokeRouteCredential :exec
UPDATE route_credentials
SET revoked_at = COALESCE(revoked_at, CAST(sqlc.arg(revoked_at) AS INTEGER))
WHERE route_id = sqlc.arg(route_id);

-- name: GetRouteVersion :one
SELECT version
FROM routes
WHERE id = sqlc.arg(route_id);

-- name: ListActiveHostnameRouteVersions :many
SELECT id, version
FROM routes
WHERE hostname_id = sqlc.arg(hostname_id) AND status = 'active'
ORDER BY id;

-- name: ListAbandonedTemporaryRoutes :many
SELECT hostnames.id AS hostname_id, routes.id AS route_id
FROM hostnames
JOIN routes ON routes.hostname_id = hostnames.id
WHERE hostnames.kind = 'temporary'
    AND hostnames.status = 'active'
    AND routes.status = 'active'
    AND NOT EXISTS (
        SELECT 1
        FROM route_sessions
        WHERE route_sessions.route_id = routes.id
            AND route_sessions.expires_at > sqlc.arg(expired_before)
    )
ORDER BY routes.id;

-- name: RetireAbandonedTemporaryHostnames :exec
UPDATE hostnames
SET status = 'retired', deactivated_at = CAST(sqlc.arg(deactivated_at) AS INTEGER)
WHERE kind = 'temporary'
    AND status = 'pending_route'
    AND created_at <= sqlc.arg(created_before);
