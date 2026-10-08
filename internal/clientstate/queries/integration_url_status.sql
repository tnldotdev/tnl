-- name: StatusIntegrationURLs :many
SELECT h.server_origin, h.project_key, h.namespace, h.purpose, h.hostname,
  COALESCE(p.expires_at, 0) AS publisher_expires_at
FROM integration_url_hostnames h LEFT JOIN integration_url_publishers p
  ON p.server_origin = h.server_origin AND p.hostname = h.hostname
WHERE h.purpose IN ('oauth', 'hooks')
ORDER BY h.server_origin, h.project_key, h.namespace, h.purpose;

-- name: StatusWebhookDeclarations :many
SELECT t.server_origin, t.integration_group, e.name, e.service, e.path, e.definition, e.fingerprint,
  t.id AS tunnel_id, t.project_root, t.service AS tunnel_service, t.hostname AS app_hostname, t.state,
  t.public_url_id, t.publish_run_number
FROM webhook_endpoints e JOIN local_tunnels t ON t.id = e.tunnel_id
WHERE t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now)
  AND t.state IN ('starting', 'provisioning', 'ready')
ORDER BY t.server_origin, t.integration_group, e.name, t.id;

-- name: StatusWebhookOwners :many
SELECT owner.server_origin, owner.integration_group, owner.name, t.id AS tunnel_id,
  t.project_root, t.service, t.hostname AS app_hostname, t.state, t.public_url_id, t.publish_run_number
FROM webhook_owners owner JOIN local_tunnels t ON t.id = owner.tunnel_id
WHERE t.stopped_at IS NULL AND t.lease_expires_at > sqlc.arg(now)
ORDER BY owner.server_origin, owner.integration_group, owner.name;
