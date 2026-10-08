-- name: InitializeProjectAlias :exec
INSERT INTO project_aliases (
    id, server_origin, project_key, team_id, membership_id, namespace, name,
    hostname, service, fingerprint, selected_project, selection_revision
)
SELECT sqlc.arg(alias_id), t.server_origin, sqlc.arg(project_key), sqlc.arg(team_id),
    sqlc.arg(membership_id), sqlc.arg(namespace), sqlc.arg(name), sqlc.arg(hostname),
    sqlc.arg(service), sqlc.arg(fingerprint), sqlc.arg(project_key), 1
FROM local_tunnels t
WHERE t.id = sqlc.arg(tunnel_id) AND t.server_origin = sqlc.arg(server_origin)
    AND t.service = sqlc.arg(service) AND t.integration_group = sqlc.arg(integration_group)
    AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now)
ON CONFLICT DO NOTHING;

-- name: ProjectAliasByScope :one
SELECT * FROM project_aliases
WHERE server_origin = sqlc.arg(server_origin) AND project_key = sqlc.arg(project_key)
    AND team_id = sqlc.arg(team_id) AND membership_id = sqlc.arg(membership_id)
    AND namespace = sqlc.arg(namespace) AND name = sqlc.arg(name);

-- name: AliasDefinitionConflicts :one
SELECT count(*) FROM alias_declarations declaration
JOIN local_tunnels tunnel ON tunnel.id = declaration.tunnel_id
WHERE declaration.alias_id = sqlc.arg(alias_id) AND declaration.fingerprint <> sqlc.arg(fingerprint)
    AND tunnel.stopped_at IS NULL AND tunnel.lease_expires_at > sqlc.arg(now);

-- name: UpdateAliasDefinition :execrows
UPDATE project_aliases SET hostname = sqlc.arg(hostname), service = sqlc.arg(service),
    selection_revision = selection_revision + CASE
      WHEN fingerprint <> sqlc.arg(fingerprint) OR hostname <> sqlc.arg(hostname) OR service <> sqlc.arg(service) THEN 1 ELSE 0 END,
    fingerprint = sqlc.arg(fingerprint)
WHERE id = sqlc.arg(alias_id) AND selection_revision < 9223372036854775807;

-- name: RegisterAliasDeclaration :execrows
INSERT INTO alias_declarations (alias_id, tunnel_id, fingerprint)
SELECT sqlc.arg(alias_id), t.id, sqlc.arg(fingerprint) FROM local_tunnels t
WHERE t.id = sqlc.arg(tunnel_id) AND t.server_origin = sqlc.arg(server_origin)
    AND t.service = sqlc.arg(service) AND t.integration_group = sqlc.arg(integration_group)
    AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now)
ON CONFLICT(alias_id, tunnel_id) DO UPDATE SET fingerprint = excluded.fingerprint;

-- name: LockAliasSelection :one
UPDATE project_aliases SET selection_revision = selection_revision
WHERE server_origin = sqlc.arg(server_origin) AND project_key = sqlc.arg(project_key)
    AND team_id = sqlc.arg(team_id) AND membership_id = sqlc.arg(membership_id)
    AND namespace = sqlc.arg(namespace) AND name = sqlc.arg(name)
RETURNING *;

-- name: ReadyAliasReceiver :one
SELECT t.* FROM alias_declarations declaration
JOIN project_aliases alias ON alias.id = declaration.alias_id
JOIN local_tunnels t ON t.id = declaration.tunnel_id
WHERE alias.id = sqlc.arg(alias_id) AND t.project_root = sqlc.arg(project_root)
    AND declaration.fingerprint = alias.fingerprint AND t.service = alias.service
    AND t.state = 'ready' AND t.public_url_id <> '' AND t.publish_run_number > 0
    AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now)
ORDER BY t.started_at DESC, t.id DESC LIMIT 1;

-- name: LiveAliasOwner :one
SELECT count(*) FROM alias_declarations declaration
JOIN project_aliases alias ON alias.id = declaration.alias_id
JOIN local_tunnels t ON t.id = declaration.tunnel_id
WHERE alias.id = sqlc.arg(alias_id) AND t.project_root = alias.selected_project
    AND declaration.fingerprint = alias.fingerprint AND t.service = alias.service
    AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now);

-- name: SetAliasSelectedProject :execrows
UPDATE project_aliases SET selected_project = sqlc.arg(project_root), selection_revision = selection_revision + 1
WHERE id = sqlc.arg(alias_id) AND selection_revision = sqlc.arg(expected_revision)
    AND selection_revision < 9223372036854775807;

-- name: ProjectAliasByID :one
SELECT * FROM project_aliases WHERE id = sqlc.arg(alias_id);
