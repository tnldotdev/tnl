-- name: MarkIntegrationURLReady :exec
INSERT INTO integration_url_leases (server_origin, hostname, publisher_instance_id, expires_at)
VALUES (sqlc.arg(server_origin), sqlc.arg(hostname), sqlc.arg(publisher_instance_id), sqlc.arg(expires_at))
ON CONFLICT(server_origin, hostname) DO UPDATE SET publisher_instance_id = excluded.publisher_instance_id, expires_at = excluded.expires_at;

-- name: SaveIntegrationURLEndpoint :exec
INSERT INTO integration_url_endpoints (server_origin, hostname, public_url_id, public_url)
VALUES (sqlc.arg(server_origin), sqlc.arg(hostname), sqlc.arg(public_url_id), sqlc.arg(public_url))
ON CONFLICT(server_origin, hostname) DO UPDATE SET public_url_id=excluded.public_url_id, public_url=excluded.public_url;

-- name: IntegrationURLEndpoint :one
SELECT public_url FROM integration_url_endpoints
WHERE server_origin=sqlc.arg(server_origin) AND hostname=sqlc.arg(hostname);

-- name: IntegrationURLReady :one
SELECT count(*) FROM integration_url_leases
WHERE server_origin = sqlc.arg(server_origin) AND hostname = sqlc.arg(hostname) AND expires_at > sqlc.arg(now);

-- name: ClearIntegrationURLReady :exec
DELETE FROM integration_url_leases WHERE server_origin = sqlc.arg(server_origin)
  AND hostname = sqlc.arg(hostname) AND publisher_instance_id = sqlc.arg(publisher_instance_id);
