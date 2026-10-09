-- name: GetWebhookCatalog :one
SELECT source_json, etag, checked_at, expires_at FROM webhook_catalog
WHERE provider = sqlc.arg(provider);

-- name: PutWebhookCatalog :exec
INSERT INTO webhook_catalog (provider, source_json, etag, checked_at, expires_at)
VALUES (sqlc.arg(provider), sqlc.arg(source_json), sqlc.arg(etag), sqlc.arg(checked_at), sqlc.arg(expires_at))
ON CONFLICT(provider) DO UPDATE SET source_json = excluded.source_json, etag = excluded.etag,
  checked_at = excluded.checked_at, expires_at = excluded.expires_at;
