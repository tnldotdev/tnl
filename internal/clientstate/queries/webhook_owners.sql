-- name: ClaimWebhookReceiver :execrows
INSERT INTO webhook_owners (server_origin, integration_group, name, tunnel_id)
SELECT t.server_origin, t.integration_group, e.name, t.id
FROM local_tunnels t JOIN webhook_endpoints e ON e.tunnel_id = t.id AND e.service = t.service
WHERE t.id = sqlc.arg(tunnel_id) AND t.server_origin = sqlc.arg(server_origin)
  AND t.integration_group = sqlc.arg(integration_group) AND e.name = sqlc.arg(name)
  AND e.fingerprint = sqlc.arg(fingerprint) AND t.state = 'ready'
  AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now)
ON CONFLICT DO NOTHING;

-- name: DeleteExpiredWebhookOwner :exec
DELETE FROM webhook_owners AS o WHERE o.server_origin = sqlc.arg(server_origin)
  AND o.integration_group = sqlc.arg(integration_group) AND o.name = sqlc.arg(name)
  AND NOT EXISTS (
    SELECT 1 FROM local_tunnels t WHERE t.id = o.tunnel_id
      AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now)
  );

-- name: ReleaseWebhookReceiver :execrows
DELETE FROM webhook_owners WHERE server_origin = sqlc.arg(server_origin)
  AND integration_group = sqlc.arg(integration_group) AND name = sqlc.arg(name) AND tunnel_id = sqlc.arg(tunnel_id);

-- name: ExclusiveWebhookReceiver :one
SELECT t.id, t.server_origin, t.integration_group, t.hostname, t.target, t.public_url_id, t.publish_run_number
FROM webhook_owners owner JOIN local_tunnels t ON t.id = owner.tunnel_id
JOIN webhook_endpoints e ON e.tunnel_id = t.id AND e.name = owner.name AND e.service = t.service
WHERE owner.server_origin = sqlc.arg(server_origin) AND owner.integration_group = sqlc.arg(integration_group)
  AND owner.name = sqlc.arg(name) AND e.fingerprint = sqlc.arg(fingerprint)
  AND t.state = 'ready' AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now);

-- name: GetWebhookHostname :one
SELECT hostname FROM integration_url_hostnames
WHERE server_origin = sqlc.arg(server_origin) AND project_key = sqlc.arg(project_key)
  AND namespace = sqlc.arg(namespace) AND purpose = 'hooks';

-- name: WebhookOwnerID :one
SELECT owner.tunnel_id FROM webhook_owners owner JOIN local_tunnels t ON t.id = owner.tunnel_id
WHERE owner.server_origin = sqlc.arg(server_origin) AND owner.integration_group = sqlc.arg(integration_group)
  AND owner.name = sqlc.arg(name) AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now);

-- name: ForceWebhookReceiver :execrows
UPDATE webhook_owners SET tunnel_id = sqlc.arg(tunnel_id)
WHERE server_origin = sqlc.arg(server_origin) AND integration_group = sqlc.arg(integration_group)
  AND name = sqlc.arg(name);

-- name: ReadyExclusiveReceiver :one
SELECT COUNT(*) FROM local_tunnels t JOIN webhook_endpoints e ON e.tunnel_id = t.id AND e.service = t.service
WHERE t.id = sqlc.arg(tunnel_id) AND t.server_origin = sqlc.arg(server_origin)
  AND t.integration_group = sqlc.arg(integration_group) AND e.name = sqlc.arg(name)
  AND e.fingerprint = sqlc.arg(fingerprint) AND t.state = 'ready'
  AND t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now);
