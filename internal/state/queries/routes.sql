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
WHERE hostname = sqlc.arg(hostname) AND status IN ('active', 'suspended');

-- name: GetActiveSignedRouteIDByHostname :one
SELECT id
FROM routes
WHERE hostname = sqlc.arg(hostname)
    AND status IN ('active', 'suspended')
    AND authorization_id IS NOT NULL;

-- name: GetRouteByID :one
SELECT * FROM routes WHERE id = sqlc.arg(route_id);

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

-- name: ReplaceSignedRoute :execrows
UPDATE routes
SET
    local_target = sqlc.arg(local_target),
    version = sqlc.arg(version),
    authorization_issuer = sqlc.arg(authorization_issuer),
    authorization_id = sqlc.arg(authorization_id),
    authorization_key_id = sqlc.arg(authorization_key_id),
    authorization_retry_id = sqlc.arg(authorization_retry_id),
    authorization_revision = sqlc.arg(authorization_revision),
    authorization_expires_at = sqlc.arg(authorization_expires_at),
    authorization_request_hash = sqlc.arg(authorization_request_hash),
    authorization_ip_policy_hash = sqlc.arg(authorization_ip_policy_hash)
WHERE id = sqlc.arg(route_id) AND status = 'active';

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

-- name: InsertSignedRoute :exec
INSERT INTO routes (
    id,
    hostname,
    local_target,
    status,
    version,
    authorization_issuer,
    authorization_id,
    authorization_key_id,
    authorization_retry_id,
    authorization_revision,
    authorization_expires_at,
    authorization_request_hash,
    authorization_ip_policy_hash,
    created_at
) VALUES (
    sqlc.arg(route_id),
    sqlc.arg(hostname),
    sqlc.arg(local_target),
    'active',
    1,
    sqlc.arg(authorization_issuer),
    sqlc.arg(authorization_id),
    sqlc.arg(authorization_key_id),
    sqlc.arg(authorization_retry_id),
    sqlc.arg(authorization_revision),
    sqlc.arg(authorization_expires_at),
    sqlc.arg(authorization_request_hash),
    sqlc.arg(authorization_ip_policy_hash),
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

-- name: AdvanceSignedRouteVersion :execrows
UPDATE routes
SET
    version = sqlc.arg(version),
    authorization_issuer = sqlc.arg(authorization_issuer),
    authorization_id = sqlc.arg(authorization_id),
    authorization_key_id = sqlc.arg(authorization_key_id),
    authorization_retry_id = sqlc.arg(authorization_retry_id),
    authorization_revision = sqlc.arg(authorization_revision),
    authorization_expires_at = sqlc.arg(authorization_expires_at),
    authorization_request_hash = sqlc.arg(authorization_request_hash),
    authorization_ip_policy_hash = sqlc.arg(authorization_ip_policy_hash)
WHERE id = sqlc.arg(route_id)
    AND version = sqlc.arg(previous_version)
    AND status = 'active'
    AND authorization_expires_at > sqlc.arg(now);

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
    AND routes.version = route_sessions.version
    AND route_sessions.status != 'expired'
    AND route_sessions.expires_at > sqlc.arg(now)
    AND (routes.authorization_expires_at IS NULL OR routes.authorization_expires_at > sqlc.arg(now));

-- name: GetRouteSessionByVersion :one
SELECT *
FROM route_sessions
WHERE route_id = sqlc.arg(route_id) AND version = sqlc.arg(version);

-- name: RestoreSignedRouteSessionRetry :execrows
UPDATE route_sessions
SET
    status = 'pending',
    server_instance_id = sqlc.arg(server_instance_id),
    publisher_public_key = NULL,
    relay_region = NULL,
    last_heartbeat_at = sqlc.arg(now),
    expires_at = sqlc.arg(expires_at)
WHERE id = sqlc.arg(session_id)
    AND route_id = sqlc.arg(route_id)
    AND version = sqlc.arg(version)
    AND token_id = sqlc.arg(token_id)
    AND (
        status = 'expired'
        OR expires_at <= sqlc.arg(now)
        OR server_instance_id != sqlc.arg(server_instance_id)
    );

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
WHERE route_sessions.id = sqlc.arg(session_id)
    AND route_sessions.route_id = sqlc.arg(route_id)
    AND route_sessions.version = sqlc.arg(version)
    AND route_sessions.status IN ('pending', 'starting')
    AND route_sessions.expires_at > sqlc.arg(now)
    AND EXISTS (
        SELECT 1 FROM routes
        WHERE routes.id = route_sessions.route_id
            AND routes.status = 'active'
            AND routes.version = route_sessions.version
            AND (routes.authorization_expires_at IS NULL OR routes.authorization_expires_at > sqlc.arg(now))
    );

-- name: ReadyRouteSession :execrows
UPDATE route_sessions
SET status = 'ready'
WHERE route_sessions.id = sqlc.arg(session_id)
    AND route_sessions.route_id = sqlc.arg(route_id)
    AND route_sessions.version = sqlc.arg(version)
    AND route_sessions.status = 'starting'
    AND route_sessions.expires_at > sqlc.arg(now)
    AND EXISTS (
        SELECT 1 FROM routes
        WHERE routes.id = route_sessions.route_id
            AND routes.status = 'active'
            AND routes.version = route_sessions.version
            AND (routes.authorization_expires_at IS NULL OR routes.authorization_expires_at > sqlc.arg(now))
    );

-- name: GetRouteSessionStatus :one
SELECT status
FROM route_sessions
WHERE route_sessions.id = sqlc.arg(session_id)
    AND route_sessions.route_id = sqlc.arg(route_id)
    AND route_sessions.version = sqlc.arg(version)
    AND route_sessions.expires_at > sqlc.arg(now)
    AND EXISTS (
        SELECT 1 FROM routes
        WHERE routes.id = route_sessions.route_id
            AND routes.status = 'active'
            AND routes.version = route_sessions.version
            AND (routes.authorization_expires_at IS NULL OR routes.authorization_expires_at > sqlc.arg(now))
    );

-- name: HeartbeatRouteSession :execrows
UPDATE route_sessions
SET
    last_heartbeat_at = sqlc.arg(last_heartbeat_at),
    expires_at = sqlc.arg(expires_at)
WHERE route_sessions.id = sqlc.arg(session_id)
    AND route_sessions.route_id = sqlc.arg(route_id)
    AND route_sessions.version = sqlc.arg(version)
    AND route_sessions.status != 'expired'
    AND route_sessions.expires_at > sqlc.arg(now)
    AND EXISTS (
        SELECT 1 FROM routes
        WHERE routes.id = route_sessions.route_id
            AND (routes.authorization_expires_at IS NULL OR routes.authorization_expires_at > sqlc.arg(now))
    );

-- name: HeartbeatRenewedRouteSession :execrows
UPDATE route_sessions
SET
    last_heartbeat_at = sqlc.arg(last_heartbeat_at),
    expires_at = sqlc.arg(expires_at)
WHERE route_sessions.id = sqlc.arg(session_id)
    AND route_sessions.route_id = sqlc.arg(route_id)
    AND route_sessions.version = sqlc.arg(version)
    AND route_sessions.status != 'expired'
    AND EXISTS (
        SELECT 1 FROM routes
        WHERE routes.id = route_sessions.route_id
            AND routes.status = 'active'
            AND routes.version = route_sessions.version
            AND routes.authorization_expires_at > sqlc.arg(now)
    );

-- name: RenewRouteAuthorization :execrows
UPDATE routes
SET
    authorization_issuer = sqlc.arg(next_issuer),
    authorization_id = sqlc.arg(next_authorization_id),
    authorization_key_id = sqlc.arg(next_key_id),
    authorization_retry_id = sqlc.arg(next_retry_id),
    authorization_revision = sqlc.arg(next_revision),
    authorization_expires_at = sqlc.arg(next_expires_at),
    authorization_request_hash = sqlc.arg(next_request_hash),
    authorization_ip_policy_hash = sqlc.arg(next_ip_policy_hash)
WHERE id = sqlc.arg(route_id)
    AND status = 'active'
    AND authorization_issuer = sqlc.arg(previous_issuer)
    AND authorization_id = sqlc.arg(previous_authorization_id)
    AND authorization_key_id = sqlc.arg(previous_key_id)
    AND authorization_retry_id = sqlc.arg(previous_retry_id)
    AND authorization_revision = sqlc.arg(previous_revision)
    AND authorization_expires_at = sqlc.arg(previous_expires_at);

-- name: InsertRouteAllowedIPPrefix :exec
INSERT INTO route_allowed_ip_prefixes (route_id, route_version, position, prefix)
VALUES (sqlc.arg(route_id), sqlc.arg(route_version), sqlc.arg(position), sqlc.arg(prefix));

-- name: ListRouteAllowedIPPrefixes :many
SELECT prefix
FROM route_allowed_ip_prefixes
WHERE route_id = sqlc.arg(route_id)
    AND route_version = sqlc.arg(route_version)
ORDER BY position;

-- name: GetRouteAuthorizationUseByRetry :one
SELECT *
FROM route_authorization_uses
WHERE authorization_issuer = sqlc.arg(authorization_issuer)
    AND authorization_retry_id = sqlc.arg(authorization_retry_id);

-- name: GetRouteAuthorizationUseByID :one
SELECT *
FROM route_authorization_uses
WHERE authorization_issuer = sqlc.arg(authorization_issuer)
    AND authorization_id = sqlc.arg(authorization_id);

-- name: InsertRouteAuthorizationUse :exec
INSERT INTO route_authorization_uses (
    authorization_issuer,
    authorization_id,
    authorization_key_id,
    authorization_retry_id,
    authorization_revision,
    authorization_expires_at,
    operation,
    route_id,
    route_version,
    hostname,
    request_hash,
    ip_policy_hash,
    created_at
) VALUES (
    sqlc.arg(authorization_issuer),
    sqlc.arg(authorization_id),
    sqlc.arg(authorization_key_id),
    sqlc.arg(authorization_retry_id),
    sqlc.arg(authorization_revision),
    sqlc.arg(authorization_expires_at),
    sqlc.arg(operation),
    sqlc.arg(route_id),
    sqlc.arg(route_version),
    sqlc.arg(hostname),
    sqlc.arg(request_hash),
    sqlc.arg(ip_policy_hash),
    sqlc.arg(created_at)
);

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

-- name: DeleteActiveSignedRoute :execrows
UPDATE routes
SET
    status = 'deleted',
    deleted_at = CAST(sqlc.arg(deleted_at) AS INTEGER)
WHERE id = sqlc.arg(route_id)
    AND authorization_id IS NOT NULL
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
