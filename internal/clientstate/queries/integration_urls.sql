-- name: MarkIntegrationURLReady :exec
INSERT INTO integration_url_publishers (server_origin, hostname, publisher_instance_id, expires_at)
VALUES (sqlc.arg(server_origin), sqlc.arg(hostname), sqlc.arg(publisher_instance_id), sqlc.arg(expires_at))
ON CONFLICT(server_origin, hostname) DO UPDATE SET publisher_instance_id = excluded.publisher_instance_id, expires_at = excluded.expires_at;

-- name: IntegrationURLReady :one
SELECT count(*) FROM integration_url_publishers
WHERE server_origin = sqlc.arg(server_origin) AND hostname = sqlc.arg(hostname) AND expires_at > sqlc.arg(now);

-- name: ClearIntegrationURLReady :exec
DELETE FROM integration_url_publishers WHERE server_origin = sqlc.arg(server_origin)
  AND hostname = sqlc.arg(hostname) AND publisher_instance_id = sqlc.arg(publisher_instance_id);
