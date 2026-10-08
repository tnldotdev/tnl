-- name: MarkAliasRunReady :execrows
INSERT INTO alias_publish_runs (alias_id, owner, tunnel_id, selection_revision,
    public_url_id, publish_run_number, target_public_url_id, target_publish_run_number)
SELECT a.id, sqlc.arg(owner), t.id, a.selection_revision, sqlc.arg(public_url_id),
    sqlc.arg(publish_run_number), t.public_url_id, t.publish_run_number
FROM project_aliases a JOIN alias_declarations d ON d.alias_id = a.id
JOIN local_tunnels t ON t.id = d.tunnel_id
WHERE a.id = sqlc.arg(alias_id) AND a.selection_revision = sqlc.arg(selection_revision)
    AND t.id = sqlc.arg(tunnel_id) AND t.project_root = a.selected_project
    AND d.fingerprint = a.fingerprint AND t.service = a.service
    AND t.public_url_id = sqlc.arg(target_public_url_id) AND t.publish_run_number = sqlc.arg(target_publish_run_number)
    AND t.state = 'ready' AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now)
ON CONFLICT(alias_id) DO UPDATE SET owner = excluded.owner, tunnel_id = excluded.tunnel_id,
    selection_revision = excluded.selection_revision, public_url_id = excluded.public_url_id,
    publish_run_number = excluded.publish_run_number, target_public_url_id = excluded.target_public_url_id,
    target_publish_run_number = excluded.target_publish_run_number;

-- name: ClearAliasRun :exec
DELETE FROM alias_publish_runs WHERE alias_id = sqlc.arg(alias_id) AND owner = sqlc.arg(owner);

-- name: RecordAliasFailure :exec
UPDATE project_aliases SET failure_reason = sqlc.arg(reason)
WHERE id = sqlc.arg(alias_id) AND selection_revision = sqlc.arg(selection_revision)
    AND selected_project = sqlc.arg(project_root);

-- name: StatusAliases :many
SELECT a.*, COALESCE(p.expires_at, 0) AS publisher_expires_at,
    COALESCE(r.tunnel_id, '') AS run_tunnel_id,
    COALESCE(r.public_url_id, '') AS public_url_id, COALESCE(r.publish_run_number, 0) AS publish_run_number,
    COALESCE(r.selection_revision, 0) AS run_revision, COALESCE(t.state, '') AS target_state,
    COALESCE(t.project_root, '') AS target_project, COALESCE(t.lease_expires_at, 0) AS target_expires_at,
    COALESCE(t.stopped_at, 0) AS target_stopped_at, COALESCE(t.public_url_id, '') AS target_public_url_id,
    COALESCE(t.publish_run_number, 0) AS target_publish_run_number,
    COALESCE(r.target_public_url_id, '') AS run_target_public_url_id,
    COALESCE(r.target_publish_run_number, 0) AS run_target_publish_run_number
FROM project_aliases a
LEFT JOIN alias_publish_runs r ON r.alias_id = a.id
LEFT JOIN local_tunnels t ON t.id = r.tunnel_id
LEFT JOIN integration_url_publishers p ON p.server_origin = a.server_origin AND p.hostname = a.hostname
WHERE sqlc.arg(project_root) = '' OR a.project_key = sqlc.arg(project_root) OR a.selected_project = sqlc.arg(project_root)
    OR EXISTS (SELECT 1 FROM alias_declarations declaration JOIN local_tunnels tunnel ON tunnel.id = declaration.tunnel_id
      WHERE declaration.alias_id = a.id AND tunnel.project_root = sqlc.arg(project_root))
ORDER BY a.server_origin, a.project_key, a.namespace, a.name;
