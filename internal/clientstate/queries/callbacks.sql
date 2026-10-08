-- name: SaveIntegrationURLHostname :exec
INSERT INTO integration_url_hostnames (server_origin, project_key, namespace, purpose, hostname)
VALUES (sqlc.arg(server_origin), sqlc.arg(project_key), sqlc.arg(namespace), sqlc.arg(purpose), sqlc.arg(hostname))
ON CONFLICT DO NOTHING;

-- name: GetIntegrationURLHostname :one
SELECT hostname FROM integration_url_hostnames
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
    expires_at, public_url_id, publish_run_number
)
SELECT t.server_origin, sqlc.arg(hostname), sqlc.arg(state_digest), t.id,
    sqlc.arg(callback_path), sqlc.arg(callback_query), sqlc.arg(expires_at),
    t.public_url_id, t.publish_run_number
FROM local_tunnels t
WHERE t.id = sqlc.arg(tunnel_id) AND t.server_origin = sqlc.arg(server_origin)
  AND t.integration_group = sqlc.arg(integration_group) AND t.state = 'ready'
  AND t.public_url_id = sqlc.arg(public_url_id) AND t.publish_run_number = sqlc.arg(publish_run_number)
  AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now)
  AND (SELECT count(*) FROM oauth_callbacks WHERE server_origin = sqlc.arg(server_origin)
       AND hostname = sqlc.arg(hostname)) < 1024
ON CONFLICT DO NOTHING;

-- name: GetCurrentOAuthCallback :one
SELECT c.callback_path, c.callback_query, t.id AS tunnel_id, t.hostname, t.public_url_id, t.publish_run_number
FROM oauth_callbacks c JOIN local_tunnels t ON t.id = c.tunnel_id
WHERE c.server_origin = sqlc.arg(server_origin) AND c.hostname = sqlc.arg(hostname)
  AND c.state_digest = sqlc.arg(state_digest) AND c.callback_path = sqlc.arg(callback_path)
  AND c.expires_at > sqlc.arg(now) AND t.lease_expires_at > sqlc.arg(now)
  AND t.state = 'ready' AND t.stopped_at IS NULL AND t.server_origin = c.server_origin
  AND t.public_url_id = c.public_url_id AND t.publish_run_number = c.publish_run_number;

-- name: DeleteOAuthCallback :execrows
DELETE FROM oauth_callbacks WHERE server_origin = sqlc.arg(server_origin)
  AND hostname = sqlc.arg(hostname) AND state_digest = sqlc.arg(state_digest);
