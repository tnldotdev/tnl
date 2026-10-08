-- name: MarkIntegrationURLReady :exec
INSERT INTO integration_url_publishers (server_origin, hostname, owner, expires_at)
VALUES (sqlc.arg(server_origin), sqlc.arg(hostname), sqlc.arg(owner), sqlc.arg(expires_at))
ON CONFLICT(server_origin, hostname) DO UPDATE SET owner = excluded.owner, expires_at = excluded.expires_at;

-- name: IntegrationURLReady :one
SELECT count(*) FROM integration_url_publishers
WHERE server_origin = sqlc.arg(server_origin) AND hostname = sqlc.arg(hostname) AND expires_at > sqlc.arg(now);

-- name: ClearIntegrationURLReady :exec
DELETE FROM integration_url_publishers WHERE server_origin = sqlc.arg(server_origin)
  AND hostname = sqlc.arg(hostname) AND owner = sqlc.arg(owner);
