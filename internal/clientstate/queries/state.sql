-- name: UpsertServerProfile :exec
INSERT INTO server_profiles (origin, created_at, last_used_at)
VALUES (sqlc.arg(origin), sqlc.arg(now), sqlc.arg(now))
ON CONFLICT (origin) DO UPDATE SET last_used_at = excluded.last_used_at;

-- name: GetSelectedServer :one
SELECT selected_server_origin
FROM client_settings
WHERE id = 1;

-- name: GetSelectedTeam :one
SELECT selected_team_id
FROM server_profiles
WHERE origin = sqlc.arg(origin);

-- name: SetSelectedTeam :exec
UPDATE server_profiles
SET selected_team_id = sqlc.arg(team_id),
    last_used_at = sqlc.arg(now)
WHERE origin = sqlc.arg(origin);

-- name: SetSelectedServer :exec
UPDATE client_settings
SET selected_server_origin = sqlc.arg(origin)
WHERE id = 1;

-- name: GetInstallationID :one
SELECT installation_id
FROM client_settings
WHERE id = 1;

-- name: SetInstallationID :exec
UPDATE client_settings
SET installation_id = sqlc.arg(installation_id)
WHERE id = 1 AND installation_id = '';

-- name: GetControlSession :one
SELECT *
FROM control_sessions
WHERE server_origin = sqlc.arg(server_origin);

-- name: UpsertControlSession :exec
INSERT INTO control_sessions (
    server_origin,
    authority_endpoint,
    session_id,
    access_token,
    access_expires_at,
    refresh_token,
    refresh_expires_at,
    updated_at
) VALUES (
    sqlc.arg(server_origin),
    sqlc.arg(authority_endpoint),
    sqlc.arg(session_id),
    sqlc.arg(access_token),
    sqlc.arg(access_expires_at),
    sqlc.arg(refresh_token),
    sqlc.arg(refresh_expires_at),
    sqlc.arg(updated_at)
)
ON CONFLICT (server_origin) DO UPDATE SET
    authority_endpoint = excluded.authority_endpoint,
    session_id = excluded.session_id,
    access_token = excluded.access_token,
    access_expires_at = excluded.access_expires_at,
    refresh_token = excluded.refresh_token,
    refresh_expires_at = excluded.refresh_expires_at,
    updated_at = excluded.updated_at;

-- name: DeleteControlSession :exec
DELETE FROM control_sessions
WHERE server_origin = sqlc.arg(server_origin);

-- name: GetRouteCertificate :one
SELECT *
FROM route_certificates
WHERE server_origin = sqlc.arg(server_origin)
  AND route_id = sqlc.arg(route_id)
  AND phase = sqlc.arg(phase);

-- name: UpsertRouteCertificate :exec
INSERT INTO route_certificates (
    server_origin,
    route_id,
    phase,
    hostname,
    key_der,
    csr_der,
    certificate_pem,
    renew_at,
    issuance_id,
    route_version,
    installed,
    updated_at
) VALUES (
    sqlc.arg(server_origin),
    sqlc.arg(route_id),
    sqlc.arg(phase),
    sqlc.arg(hostname),
    sqlc.arg(key_der),
    sqlc.arg(csr_der),
    sqlc.narg(certificate_pem),
    sqlc.narg(renew_at),
    sqlc.arg(issuance_id),
    sqlc.arg(route_version),
    sqlc.arg(installed),
    sqlc.arg(updated_at)
)
ON CONFLICT (server_origin, route_id, phase) DO UPDATE SET
    hostname = excluded.hostname,
    key_der = excluded.key_der,
    csr_der = excluded.csr_der,
    certificate_pem = excluded.certificate_pem,
    renew_at = excluded.renew_at,
    issuance_id = excluded.issuance_id,
    route_version = excluded.route_version,
    installed = excluded.installed,
    updated_at = excluded.updated_at;

-- name: DeleteRouteCertificate :exec
DELETE FROM route_certificates
WHERE server_origin = sqlc.arg(server_origin)
  AND route_id = sqlc.arg(route_id)
  AND phase = sqlc.arg(phase);

-- name: InsertTunnel :exec
INSERT INTO local_tunnels (
    id,
    command,
    process_id,
    server_origin,
    project_root,
    service,
    hostname,
    target,
    framework,
    route_id,
    route_version,
    state,
    started_at,
    updated_at,
    heartbeat_at,
    lease_expires_at,
    last_error
) VALUES (
    sqlc.arg(id),
    sqlc.arg(command),
    sqlc.arg(process_id),
    sqlc.arg(server_origin),
    sqlc.arg(project_root),
    sqlc.arg(service),
    '',
    sqlc.arg(target),
    '',
    '',
    0,
    'starting',
    sqlc.arg(now),
    sqlc.arg(now),
    sqlc.arg(now),
    sqlc.arg(lease_expires_at),
    ''
);

-- name: SetTunnelDevTarget :execrows
UPDATE local_tunnels
SET target = sqlc.arg(target),
    framework = sqlc.arg(framework),
    updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND stopped_at IS NULL;

-- name: SetTunnelRoute :execrows
UPDATE local_tunnels
SET route_id = sqlc.arg(route_id),
    hostname = sqlc.arg(hostname),
    state = 'provisioning',
    updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND stopped_at IS NULL;

-- name: SetTunnelProvisioning :execrows
UPDATE local_tunnels
SET route_version = sqlc.arg(route_version),
    state = 'provisioning',
    updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND stopped_at IS NULL;

-- name: SetTunnelReady :execrows
UPDATE local_tunnels
SET hostname = sqlc.arg(hostname),
    route_version = sqlc.arg(route_version),
    state = 'ready',
    updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND stopped_at IS NULL;

-- name: SetTunnelDraining :execrows
UPDATE local_tunnels
SET state = 'draining', updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND stopped_at IS NULL;

-- name: HeartbeatTunnel :execrows
UPDATE local_tunnels
SET heartbeat_at = sqlc.arg(now), lease_expires_at = sqlc.arg(lease_expires_at)
WHERE id = sqlc.arg(id) AND stopped_at IS NULL;

-- name: FinishTunnel :execrows
UPDATE local_tunnels
SET state = sqlc.arg(state),
    last_error = sqlc.arg(last_error),
    updated_at = sqlc.arg(now),
    heartbeat_at = sqlc.arg(now),
    lease_expires_at = sqlc.arg(now),
    stopped_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND stopped_at IS NULL;

-- name: ListOpenTunnels :many
SELECT *
FROM local_tunnels
WHERE stopped_at IS NULL
ORDER BY started_at, id;

-- name: ListOpenTunnelsForProject :many
SELECT *
FROM local_tunnels
WHERE stopped_at IS NULL AND project_root = sqlc.arg(project_root)
ORDER BY started_at, id;

-- name: DeleteOldTunnels :exec
DELETE FROM local_tunnels
WHERE stopped_at < sqlc.arg(terminal_before)
   OR (stopped_at IS NULL AND lease_expires_at < sqlc.arg(stale_before));
