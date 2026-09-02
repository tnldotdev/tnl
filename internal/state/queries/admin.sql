-- name: ListAdminRoutes :many
SELECT * FROM routes
WHERE CAST(sqlc.arg(cursor) AS TEXT) = '' OR id > CAST(sqlc.arg(cursor) AS TEXT)
ORDER BY id
LIMIT sqlc.arg(limit);

-- name: GetAdminRoute :one
SELECT * FROM routes WHERE id = sqlc.arg(route_id);

-- name: SuspendAdminRoute :execrows
UPDATE routes
SET status = 'suspended',
    suspension_revision = sqlc.arg(revision),
    suspension_reason = sqlc.arg(reason),
    suspended_at = sqlc.arg(suspended_at)
WHERE id = sqlc.arg(route_id)
    AND status = 'active'
    AND suspension_revision < sqlc.arg(revision);

-- name: ResumeAdminRoute :execrows
UPDATE routes
SET status = 'active',
    version = version + 1,
    suspension_revision = sqlc.arg(revision),
    suspended_at = NULL
WHERE routes.id = sqlc.arg(route_id)
    AND routes.status = 'suspended'
    AND routes.suspension_revision < sqlc.arg(revision)
    AND (
        hostname_id IS NULL OR EXISTS (
            SELECT 1 FROM hostnames
            WHERE hostnames.id = routes.hostname_id AND hostnames.status = 'active'
        )
    );

-- name: ListAdminHostnames :many
SELECT * FROM hostnames
WHERE CAST(sqlc.arg(cursor) AS TEXT) = '' OR id > CAST(sqlc.arg(cursor) AS TEXT)
ORDER BY id
LIMIT sqlc.arg(limit);

-- name: GetAdminHostname :one
SELECT * FROM hostnames WHERE id = sqlc.arg(hostname_id);

-- name: RemoveAdminHostname :execrows
UPDATE hostnames
SET status = CASE kind
        WHEN 'managed' THEN 'inactive'
        WHEN 'custom_domain' THEN 'available'
        ELSE 'retired'
    END,
    identity_id = CASE kind WHEN 'custom_domain' THEN NULL ELSE identity_id END,
    deactivated_at = sqlc.arg(deactivated_at),
    quarantine_reason = NULL,
    quarantined_at = NULL
WHERE id = sqlc.arg(hostname_id)
    AND status NOT IN ('inactive', 'available', 'retired');

-- name: QuarantineAdminHostname :execrows
UPDATE hostnames
SET status = 'quarantined',
    quarantine_reason = sqlc.arg(reason),
    quarantined_at = sqlc.arg(quarantined_at),
    deactivated_at = sqlc.arg(quarantined_at)
WHERE id = sqlc.arg(hostname_id)
    AND identity_id IS NOT NULL
    AND status != 'quarantined';

-- name: SuspendAdminHostnameRoutes :exec
UPDATE routes
SET status = 'suspended',
    suspension_revision = suspension_revision + 1,
    suspension_reason = sqlc.arg(reason),
    suspended_at = sqlc.arg(suspended_at)
WHERE hostname_id = sqlc.arg(hostname_id) AND status = 'active';

-- name: ListCurrentRoutesForAdminHostname :many
SELECT id, version, status FROM routes
WHERE hostname_id = sqlc.arg(hostname_id) AND status IN ('active', 'suspended')
ORDER BY id;

-- name: ListAdminCredentials :many
SELECT route_credentials.id, route_credentials.route_id, route_credentials.created_at, route_credentials.revoked_at
FROM route_credentials
WHERE CAST(sqlc.arg(cursor) AS TEXT) = '' OR route_credentials.id > CAST(sqlc.arg(cursor) AS TEXT)
ORDER BY route_credentials.id
LIMIT sqlc.arg(limit);

-- name: GetAdminCredentialRoute :one
SELECT route_id FROM route_credentials WHERE id = sqlc.arg(credential_id);

-- name: RevokeAdminCredential :execrows
UPDATE route_credentials
SET revoked_at = COALESCE(revoked_at, sqlc.arg(revoked_at))
WHERE id = sqlc.arg(credential_id) AND revoked_at IS NULL;

-- name: ListAdminControlSessions :many
SELECT id, identity_id, authentication_method, grants, created_at,
    refresh_expires_at, access_expires_at, revoked_at
FROM control_sessions
WHERE CAST(sqlc.arg(cursor) AS TEXT) = '' OR id > CAST(sqlc.arg(cursor) AS TEXT)
ORDER BY id
LIMIT sqlc.arg(limit);

-- name: RevokeAdminControlSession :execrows
UPDATE control_sessions
SET access_token_revoked_at = COALESCE(access_token_revoked_at, sqlc.arg(revoked_at)),
    refresh_token_revoked_at = COALESCE(refresh_token_revoked_at, sqlc.arg(revoked_at)),
    revoked_at = COALESCE(revoked_at, sqlc.arg(revoked_at))
WHERE id = sqlc.arg(session_id) AND revoked_at IS NULL;

-- name: ListOperationalSwitches :many
SELECT * FROM operational_switches ORDER BY name;

-- name: GetOperationalSwitch :one
SELECT * FROM operational_switches WHERE name = sqlc.arg(name);

-- name: SetOperationalSwitch :execrows
UPDATE operational_switches
SET enabled = sqlc.arg(enabled),
    revision = revision + 1,
    updated_at = sqlc.arg(updated_at),
    updated_by = sqlc.arg(updated_by)
WHERE name = sqlc.arg(name);

-- name: InsertAdminAuditEvent :exec
INSERT INTO admin_audit_events (actor, request_id, operation, target, occurred_at)
VALUES (sqlc.arg(actor), sqlc.arg(request_id), sqlc.arg(operation), sqlc.arg(target), sqlc.arg(occurred_at));

-- name: CountAdminRoutesByStatus :one
SELECT COUNT(*) FROM routes WHERE status = sqlc.arg(status);

-- name: CountAdminAuditEvents :one
SELECT COUNT(*) FROM admin_audit_events;
