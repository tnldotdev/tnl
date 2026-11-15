-- name: SaveIntegrationURLHostname :exec
INSERT INTO integration_url_hostnames (server_origin, primary_project_root, namespace, purpose, hostname)
VALUES (sqlc.arg(server_origin), sqlc.arg(project_key), sqlc.arg(namespace), sqlc.arg(purpose), sqlc.arg(hostname))
ON CONFLICT DO NOTHING;

-- name: GetIntegrationURLHostname :one
SELECT hostname FROM integration_url_hostnames
WHERE server_origin = sqlc.arg(server_origin) AND primary_project_root = sqlc.arg(project_key)
  AND namespace = sqlc.arg(namespace) AND purpose = sqlc.arg(purpose);

-- name: SetTunnelIntegrationScope :execrows
UPDATE local_tunnels SET
    primary_project_root = sqlc.arg(primary_project_root),
    integration_namespace = sqlc.arg(integration_namespace)
WHERE id = sqlc.arg(tunnel_id) AND stopped_at IS NULL;

-- name: ExpireOAuthCallbacks :exec
DELETE FROM oauth_pending_callbacks WHERE expires_at <= sqlc.arg(now);

-- name: SaveOAuthCallback :execrows
INSERT INTO oauth_pending_callbacks (
    server_origin, hostname, state_digest, tunnel_id, primary_project_root, integration_namespace, callback_path, callback_query,
    expires_at, service_id, run_number, origin_hostname, origin_service_id, origin_run_number
)
SELECT t.server_origin, sqlc.arg(hostname), sqlc.arg(state_digest), t.id, t.primary_project_root, t.integration_namespace,
    sqlc.arg(callback_path), sqlc.arg(callback_query), sqlc.arg(expires_at),
    t.service_id, t.publish_run_number, sqlc.arg(origin_hostname), sqlc.arg(service_id), sqlc.arg(run_number)
FROM local_tunnels t
WHERE t.id = sqlc.arg(tunnel_id) AND t.server_origin = sqlc.arg(server_origin)
  AND t.primary_project_root = sqlc.arg(primary_project_root)
  AND t.integration_namespace = sqlc.arg(integration_namespace) AND t.state = 'ready'
  AND ((t.service_id = sqlc.arg(service_id) AND t.publish_run_number = sqlc.arg(run_number)
        AND (sqlc.arg(origin_hostname) = '' OR sqlc.arg(origin_hostname) = t.hostname))
    OR EXISTS (SELECT 1 FROM alias_publish_runs r JOIN project_aliases a ON a.id = r.alias_id
      JOIN alias_declarations d ON d.alias_id = a.id AND d.tunnel_id = r.tunnel_id
      JOIN integration_url_leases p ON p.server_origin = a.server_origin AND p.hostname = a.hostname
      WHERE r.tunnel_id = t.id AND a.server_origin = t.server_origin AND a.hostname = sqlc.arg(origin_hostname)
         AND a.selected_project_root = t.project_root AND a.selection_revision = r.selection_revision
         AND a.primary_project_root = t.primary_project_root AND d.integration_namespace = t.integration_namespace
         AND d.fingerprint = a.fingerprint AND t.service = a.service
         AND r.target_service_id = t.service_id AND r.target_run_number = t.publish_run_number
         AND r.service_id = sqlc.arg(service_id) AND r.run_number = sqlc.arg(run_number)
         AND p.service_id = r.service_id AND p.run_number = r.run_number
        AND p.expires_at > sqlc.arg(now)))
  AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now)
  AND (SELECT count(*) FROM oauth_pending_callbacks pending WHERE pending.server_origin = sqlc.arg(server_origin)
        AND pending.hostname = sqlc.arg(hostname)) < 1024
ON CONFLICT DO NOTHING;

-- name: GetCurrentOAuthCallback :one
SELECT c.callback_path, c.callback_query, c.expires_at, t.id AS tunnel_id, t.hostname, c.origin_hostname,
    c.origin_service_id, c.origin_run_number
FROM oauth_pending_callbacks c JOIN local_tunnels t ON t.id = c.tunnel_id
WHERE c.server_origin = sqlc.arg(server_origin) AND c.hostname = sqlc.arg(hostname)
  AND c.state_digest = sqlc.arg(state_digest) AND c.callback_path = sqlc.arg(callback_path)
  AND c.expires_at > sqlc.arg(now) AND t.lease_expires_at > sqlc.arg(now)
  AND t.state = 'ready' AND t.stopped_at IS NULL AND t.server_origin = c.server_origin
  AND t.primary_project_root = c.primary_project_root AND t.integration_namespace = c.integration_namespace
  AND t.service_id = c.service_id AND t.publish_run_number = c.run_number
  AND ((c.origin_service_id = t.service_id AND c.origin_run_number = t.publish_run_number
        AND (c.origin_hostname = '' OR c.origin_hostname = t.hostname))
    OR EXISTS (SELECT 1 FROM alias_publish_runs r JOIN project_aliases a ON a.id = r.alias_id
      JOIN alias_declarations d ON d.alias_id = a.id AND d.tunnel_id = r.tunnel_id
      JOIN integration_url_leases p ON p.server_origin = a.server_origin AND p.hostname = a.hostname
      WHERE r.tunnel_id = t.id AND a.server_origin = c.server_origin AND a.hostname = c.origin_hostname
         AND a.selected_project_root = t.project_root AND a.selection_revision = r.selection_revision
         AND a.primary_project_root = t.primary_project_root AND d.integration_namespace = t.integration_namespace
         AND d.fingerprint = a.fingerprint AND t.service = a.service
         AND r.target_service_id = t.service_id AND r.target_run_number = t.publish_run_number
         AND r.service_id = c.origin_service_id AND r.run_number = c.origin_run_number
         AND p.service_id = r.service_id AND p.run_number = r.run_number
        AND p.expires_at > sqlc.arg(now)));

-- name: SaveOAuthAliasReturn :execrows
INSERT INTO oauth_alias_handoffs (server_origin, hostname, state_digest, callback_path, service_id, run_number, created_at, expires_at)
SELECT sqlc.arg(server_origin), sqlc.arg(hostname), sqlc.arg(state_digest), sqlc.arg(callback_path), sqlc.arg(service_id), sqlc.arg(run_number), sqlc.arg(now), sqlc.arg(expires_at)
WHERE (SELECT count(*) FROM oauth_alias_handoffs handoff
    WHERE handoff.server_origin = sqlc.arg(server_origin) AND handoff.hostname = sqlc.arg(hostname)) < 1024;

-- name: GetOAuthAliasReturn :one
SELECT * FROM oauth_alias_handoffs
WHERE server_origin = sqlc.arg(server_origin) AND hostname = sqlc.arg(hostname) AND state_digest = sqlc.arg(state_digest);

-- name: ConsumeOAuthAliasReturn :execrows
UPDATE oauth_alias_handoffs SET consumed_at = sqlc.arg(now)
WHERE oauth_alias_handoffs.server_origin = sqlc.arg(server_origin)
    AND oauth_alias_handoffs.hostname = sqlc.arg(hostname)
    AND oauth_alias_handoffs.state_digest = sqlc.arg(state_digest)
    AND oauth_alias_handoffs.consumed_at IS NULL AND oauth_alias_handoffs.expires_at > sqlc.arg(now)
    AND oauth_alias_handoffs.callback_path = sqlc.arg(callback_path)
    AND oauth_alias_handoffs.service_id = sqlc.arg(service_id) AND oauth_alias_handoffs.run_number = sqlc.arg(run_number)
    AND EXISTS (
      SELECT 1 FROM project_aliases a JOIN alias_publish_runs r ON r.alias_id = a.id
      JOIN local_tunnels t ON t.id = r.tunnel_id
      JOIN alias_declarations d ON d.alias_id = a.id AND d.tunnel_id = t.id
      JOIN integration_url_leases p ON p.server_origin = a.server_origin AND p.hostname = a.hostname
      WHERE a.server_origin = oauth_alias_handoffs.server_origin AND a.hostname = oauth_alias_handoffs.hostname
        AND a.selection_revision = r.selection_revision AND a.selected_project_root = t.project_root
        AND t.server_origin = a.server_origin AND t.primary_project_root = a.primary_project_root
        AND t.integration_namespace = d.integration_namespace AND d.fingerprint = a.fingerprint AND t.service = a.service
        AND r.service_id = oauth_alias_handoffs.service_id AND r.run_number = oauth_alias_handoffs.run_number
        AND t.service_id = r.target_service_id AND t.publish_run_number = r.target_run_number
        AND p.service_id = r.service_id AND p.run_number = r.run_number AND p.expires_at > sqlc.arg(now)
        AND t.state = 'ready' AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now));

-- name: ExpireOAuthAliasReturns :exec
DELETE FROM oauth_alias_handoffs WHERE expires_at <= sqlc.arg(now);

-- name: DeleteOAuthCallback :execrows
DELETE FROM oauth_pending_callbacks WHERE server_origin = sqlc.arg(server_origin)
  AND hostname = sqlc.arg(hostname) AND state_digest = sqlc.arg(state_digest);
