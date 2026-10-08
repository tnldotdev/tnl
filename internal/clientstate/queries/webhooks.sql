-- name: RegisterWebhookEndpoint :execrows
INSERT INTO webhook_endpoints (tunnel_id, name, service, path, definition, fingerprint)
SELECT t.id, sqlc.arg(name), sqlc.arg(service), sqlc.arg(path), sqlc.arg(definition), sqlc.arg(fingerprint)
FROM local_tunnels t
WHERE t.id = sqlc.arg(tunnel_id) AND t.integration_group <> '' AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now)
  AND NOT EXISTS (
    SELECT 1 FROM webhook_endpoints e JOIN local_tunnels other ON other.id = e.tunnel_id
    WHERE other.server_origin = t.server_origin AND other.integration_group = t.integration_group
      AND other.stopped_at IS NULL AND other.lease_expires_at > sqlc.arg(now)
      AND ((e.name = sqlc.arg(name) AND e.fingerprint <> sqlc.arg(fingerprint))
           OR (e.path = sqlc.arg(path) AND e.name <> sqlc.arg(name)))
  )
ON CONFLICT(tunnel_id, name) DO UPDATE SET fingerprint = excluded.fingerprint
WHERE webhook_endpoints.fingerprint = excluded.fingerprint;

-- name: ActiveWebhookEndpoints :many
SELECT e.* FROM webhook_endpoints e JOIN local_tunnels t ON t.id = e.tunnel_id
WHERE t.server_origin = sqlc.arg(server_origin) AND t.integration_group = sqlc.arg(integration_group)
  AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now)
  AND t.state IN ('starting', 'provisioning', 'ready')
ORDER BY e.name, e.tunnel_id;

-- name: ReadyWebhookReceivers :many
SELECT t.id, t.server_origin, t.integration_group, t.hostname, t.target, t.public_url_id, t.publish_run_number, e.fingerprint
FROM webhook_endpoints e JOIN local_tunnels t ON t.id = e.tunnel_id
WHERE e.name = sqlc.arg(name) AND t.server_origin = sqlc.arg(server_origin)
  AND t.integration_group = sqlc.arg(integration_group) AND e.service = t.service
  AND t.state = 'ready' AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now)
  AND t.public_url_id <> '' AND t.publish_run_number > 0
ORDER BY t.id;

-- name: WebhookReceiverCurrent :one
SELECT count(*) FROM local_tunnels
WHERE id = sqlc.arg(tunnel_id) AND server_origin = sqlc.arg(server_origin) AND target = sqlc.arg(target)
  AND public_url_id = sqlc.arg(public_url_id) AND publish_run_number = sqlc.arg(publish_run_number)
  AND state = 'ready' AND stopped_at IS NULL AND lease_expires_at > sqlc.arg(now);
