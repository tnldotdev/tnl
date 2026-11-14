-- name: RegisterWebhookEndpoint :execrows
INSERT INTO webhook_declarations (tunnel_id, name, service, path, definition, fingerprint)
SELECT t.id, sqlc.arg(name), sqlc.arg(service), sqlc.arg(path), sqlc.arg(definition), sqlc.arg(fingerprint)
FROM local_tunnels t
WHERE t.id = sqlc.arg(tunnel_id) AND t.primary_project_root IS NOT NULL AND t.integration_namespace IS NOT NULL
  AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now)
  AND NOT EXISTS (
    SELECT 1 FROM webhook_declarations e JOIN local_tunnels other ON other.id = e.tunnel_id
    WHERE other.server_origin = t.server_origin AND other.primary_project_root = t.primary_project_root
      AND other.integration_namespace = t.integration_namespace
      AND other.stopped_at IS NULL AND other.lease_expires_at > sqlc.arg(now)
      AND ((e.name = sqlc.arg(name) AND e.fingerprint <> sqlc.arg(fingerprint))
           OR (e.path = sqlc.arg(path) AND e.name <> sqlc.arg(name)))
  )
ON CONFLICT(tunnel_id, name) DO UPDATE SET fingerprint = excluded.fingerprint
WHERE webhook_declarations.fingerprint = excluded.fingerprint;

-- name: ActiveWebhookEndpoints :many
SELECT e.* FROM webhook_declarations e JOIN local_tunnels t ON t.id = e.tunnel_id
WHERE t.server_origin = sqlc.arg(server_origin) AND t.primary_project_root = sqlc.arg(primary_project_root)
  AND t.integration_namespace = sqlc.arg(integration_namespace)
  AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now)
  AND t.state IN ('starting', 'provisioning', 'ready')
ORDER BY e.name, e.tunnel_id;

-- name: ReadyWebhookReceivers :many
SELECT t.id, t.server_origin, t.primary_project_root, t.integration_namespace, t.hostname, t.public_url, t.target, t.public_url_id, t.publish_run_number, e.fingerprint
FROM webhook_declarations e JOIN local_tunnels t ON t.id = e.tunnel_id
WHERE e.name = sqlc.arg(name) AND t.server_origin = sqlc.arg(server_origin)
  AND t.primary_project_root = sqlc.arg(primary_project_root) AND t.integration_namespace = sqlc.arg(integration_namespace)
  AND e.service = t.service
  AND t.state = 'ready' AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now)
  AND t.public_url_id <> '' AND t.publish_run_number > 0
ORDER BY t.id;

-- name: WebhookReceiverCurrent :one
SELECT count(*) FROM local_tunnels
WHERE id = sqlc.arg(tunnel_id) AND server_origin = sqlc.arg(server_origin) AND target = sqlc.arg(target)
  AND public_url_id = sqlc.arg(public_url_id) AND publish_run_number = sqlc.arg(publish_run_number)
  AND state = 'ready' AND stopped_at IS NULL AND lease_expires_at > sqlc.arg(now);
