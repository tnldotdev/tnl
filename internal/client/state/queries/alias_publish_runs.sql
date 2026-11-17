-- name: MarkAliasRunReady :execrows
INSERT INTO alias_publish_runs (alias_id, owner, tunnel_id, selection_revision,
    service_id, run_number, target_service_id, target_run_number)
SELECT a.id, sqlc.arg(owner), t.id, a.selection_revision, sqlc.arg(service_id),
    sqlc.arg(run_number), t.service_id, t.publish_run_number
FROM project_aliases a JOIN alias_declarations d ON d.alias_id = a.id
JOIN local_tunnels t ON t.id = d.tunnel_id
WHERE a.id = sqlc.arg(alias_id) AND a.selection_revision = sqlc.arg(selection_revision)
    AND t.id = sqlc.arg(tunnel_id) AND t.project_root = a.selected_project_root
    AND t.server_origin = a.server_origin AND t.primary_project_root = a.primary_project_root
    AND t.integration_namespace = d.integration_namespace
    AND t.primary_project_root = sqlc.arg(primary_project_root)
    AND t.integration_namespace = sqlc.arg(integration_namespace)
    AND d.fingerprint = a.fingerprint AND t.service = a.service
    AND t.service_id = sqlc.arg(target_service_id) AND t.publish_run_number = sqlc.arg(target_run_number)
    AND t.state = 'ready' AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now)
    AND EXISTS (SELECT 1 FROM integration_url_leases p
        WHERE p.server_origin = a.server_origin AND p.hostname = a.hostname
          AND p.service_id = sqlc.arg(service_id) AND p.run_number = sqlc.arg(run_number)
          AND p.expires_at > sqlc.arg(now))
ON CONFLICT(alias_id) DO UPDATE SET owner = excluded.owner, tunnel_id = excluded.tunnel_id,
    selection_revision = excluded.selection_revision, service_id = excluded.service_id,
    run_number = excluded.run_number, target_service_id = excluded.target_service_id,
    target_run_number = excluded.target_run_number;

-- name: ClearAliasRun :exec
DELETE FROM alias_publish_runs WHERE alias_id = sqlc.arg(alias_id) AND owner = sqlc.arg(owner);

-- name: RecordAliasFailure :exec
UPDATE project_aliases SET failure_reason = sqlc.arg(reason)
WHERE id = sqlc.arg(alias_id) AND selection_revision = sqlc.arg(selection_revision)
    AND selected_project_root = sqlc.arg(project_root);

-- name: StatusAliases :many
SELECT a.*, COALESCE(p.expires_at, 0) AS publisher_expires_at,
    COALESCE(r.tunnel_id, '') AS run_tunnel_id,
    COALESCE(r.service_id, '') AS service_id, COALESCE(r.run_number, 0) AS run_number,
    COALESCE(r.selection_revision, 0) AS run_revision, COALESCE(t.state, '') AS target_state,
    COALESCE(t.project_root, '') AS target_project, COALESCE(t.lease_expires_at, 0) AS target_expires_at,
    COALESCE(t.stopped_at, 0) AS target_stopped_at, COALESCE(t.service_id, '') AS target_service_id,
    COALESCE(t.publish_run_number, 0) AS target_run_number,
    COALESCE(r.target_service_id, '') AS run_target_service_id,
    COALESCE(r.target_run_number, 0) AS run_target_run_number
FROM project_aliases a
LEFT JOIN alias_publish_runs r ON r.alias_id = a.id
LEFT JOIN local_tunnels t ON t.id = r.tunnel_id
LEFT JOIN integration_url_leases p ON p.server_origin = a.server_origin AND p.hostname = a.hostname
    AND p.service_id = r.service_id AND p.run_number = r.run_number
WHERE sqlc.arg(project_root) = '' OR a.primary_project_root = sqlc.arg(project_root) OR a.selected_project_root = sqlc.arg(project_root)
    OR EXISTS (SELECT 1 FROM alias_declarations declaration JOIN local_tunnels tunnel ON tunnel.id = declaration.tunnel_id
      WHERE declaration.alias_id = a.id AND tunnel.project_root = sqlc.arg(project_root))
ORDER BY a.server_origin, a.primary_project_root, a.namespace, a.name;
