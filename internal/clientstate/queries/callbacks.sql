-- name: SaveIntegrationURLHostname :exec
INSERT INTO integration_url_hostnames (server_origin, project_key, namespace, purpose, hostname, label_version)
VALUES (sqlc.arg(server_origin), sqlc.arg(project_key), sqlc.arg(namespace), sqlc.arg(purpose), sqlc.arg(hostname), 2)
ON CONFLICT DO NOTHING;

-- name: ReplaceLegacyIntegrationURLHostname :exec
UPDATE integration_url_hostnames SET hostname = sqlc.arg(hostname), label_version = 2
WHERE server_origin = sqlc.arg(server_origin) AND project_key = sqlc.arg(project_key)
  AND namespace = sqlc.arg(namespace) AND purpose = sqlc.arg(purpose)
  AND purpose IN ('oauth', 'hooks') AND label_version = 1;

-- name: GetIntegrationURLHostname :one
SELECT hostname, label_version FROM integration_url_hostnames
WHERE server_origin = sqlc.arg(server_origin) AND project_key = sqlc.arg(project_key)
  AND namespace = sqlc.arg(namespace) AND purpose = sqlc.arg(purpose);

-- name: SetTunnelIntegrationGroup :execrows
UPDATE local_tunnels SET integration_group = sqlc.arg(integration_group)
WHERE id = sqlc.arg(tunnel_id) AND stopped_at IS NULL;

-- name: ExpireOAuthCallbacks :exec
DELETE FROM oauth_callbacks WHERE expires_at <= sqlc.arg(now);

-- name: SaveOAuthCallback :execrows
INSERT INTO oauth_callbacks (
    server_origin, hostname, state_digest, tunnel_id, callback_path, callback_query,
    expires_at, public_url_id, publish_run_number, origin_hostname, origin_public_url_id, origin_publish_run_number
)
SELECT t.server_origin, sqlc.arg(hostname), sqlc.arg(state_digest), t.id,
    sqlc.arg(callback_path), sqlc.arg(callback_query), sqlc.arg(expires_at),
    t.public_url_id, t.publish_run_number, sqlc.arg(origin_hostname), sqlc.arg(public_url_id), sqlc.arg(publish_run_number)
FROM local_tunnels t
WHERE t.id = sqlc.arg(tunnel_id) AND t.server_origin = sqlc.arg(server_origin)
  AND t.integration_group = sqlc.arg(integration_group) AND t.state = 'ready'
  AND ((t.public_url_id = sqlc.arg(public_url_id) AND t.publish_run_number = sqlc.arg(publish_run_number)
        AND (sqlc.arg(origin_hostname) = '' OR sqlc.arg(origin_hostname) = t.hostname))
    OR EXISTS (SELECT 1 FROM alias_publish_runs r JOIN project_aliases a ON a.id = r.alias_id
      JOIN integration_url_publishers p ON p.server_origin = a.server_origin AND p.hostname = a.hostname
      WHERE r.tunnel_id = t.id AND a.server_origin = t.server_origin AND a.hostname = sqlc.arg(origin_hostname)
        AND a.selected_project = t.project_root AND a.selection_revision = r.selection_revision
        AND r.target_public_url_id = t.public_url_id AND r.target_publish_run_number = t.publish_run_number
        AND r.public_url_id = sqlc.arg(public_url_id) AND r.publish_run_number = sqlc.arg(publish_run_number)
        AND p.expires_at > sqlc.arg(now)))
  AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now)
  AND (SELECT count(*) FROM oauth_callbacks WHERE server_origin = sqlc.arg(server_origin)
       AND hostname = sqlc.arg(hostname)) < 1024
ON CONFLICT DO NOTHING;

-- name: GetCurrentOAuthCallback :one
SELECT c.callback_path, c.callback_query, c.expires_at, t.id AS tunnel_id, t.hostname, c.origin_hostname,
    c.origin_public_url_id AS public_url_id, c.origin_publish_run_number AS publish_run_number
FROM oauth_callbacks c JOIN local_tunnels t ON t.id = c.tunnel_id
WHERE c.server_origin = sqlc.arg(server_origin) AND c.hostname = sqlc.arg(hostname)
  AND c.state_digest = sqlc.arg(state_digest) AND c.callback_path = sqlc.arg(callback_path)
  AND c.expires_at > sqlc.arg(now) AND t.lease_expires_at > sqlc.arg(now)
  AND t.state = 'ready' AND t.stopped_at IS NULL AND t.server_origin = c.server_origin
  AND t.public_url_id = c.public_url_id AND t.publish_run_number = c.publish_run_number
  AND ((c.origin_public_url_id = t.public_url_id AND c.origin_publish_run_number = t.publish_run_number)
    OR EXISTS (SELECT 1 FROM alias_publish_runs r JOIN project_aliases a ON a.id = r.alias_id
      JOIN integration_url_publishers p ON p.server_origin = a.server_origin AND p.hostname = a.hostname
      WHERE r.tunnel_id = t.id AND a.server_origin = c.server_origin AND a.hostname = c.origin_hostname
        AND a.selected_project = t.project_root AND a.selection_revision = r.selection_revision
        AND r.target_public_url_id = t.public_url_id AND r.target_publish_run_number = t.publish_run_number
        AND r.public_url_id = c.origin_public_url_id AND r.publish_run_number = c.origin_publish_run_number
        AND p.expires_at > sqlc.arg(now)));

-- name: SaveOAuthAliasReturn :execrows
INSERT INTO oauth_alias_returns (server_origin, hostname, state_digest, callback_path, public_url_id, publish_run_number, expires_at)
SELECT sqlc.arg(server_origin), sqlc.arg(hostname), sqlc.arg(state_digest), sqlc.arg(callback_path), sqlc.arg(public_url_id), sqlc.arg(publish_run_number), sqlc.arg(expires_at)
WHERE (SELECT count(*) FROM oauth_alias_returns WHERE server_origin = sqlc.arg(server_origin) AND hostname = sqlc.arg(hostname)) < 1024;

-- name: GetOAuthAliasReturn :one
SELECT * FROM oauth_alias_returns
WHERE server_origin = sqlc.arg(server_origin) AND hostname = sqlc.arg(hostname) AND state_digest = sqlc.arg(state_digest);

-- name: ConsumeOAuthAliasReturn :execrows
UPDATE oauth_alias_returns SET consumed = 1
WHERE server_origin = sqlc.arg(server_origin) AND hostname = sqlc.arg(hostname) AND state_digest = sqlc.arg(state_digest)
    AND consumed = 0 AND expires_at > sqlc.arg(now) AND callback_path = sqlc.arg(callback_path)
    AND public_url_id = sqlc.arg(public_url_id) AND publish_run_number = sqlc.arg(publish_run_number);

-- name: ExpireOAuthAliasReturns :exec
DELETE FROM oauth_alias_returns WHERE expires_at <= sqlc.arg(now);

-- name: DeleteOAuthCallback :execrows
DELETE FROM oauth_callbacks WHERE server_origin = sqlc.arg(server_origin)
  AND hostname = sqlc.arg(hostname) AND state_digest = sqlc.arg(state_digest);
