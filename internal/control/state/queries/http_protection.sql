-- name: ListHTTPTemporaryBlocks :many
SELECT source_ip, expires_at
FROM control.http_temporary_blocks
WHERE resource_kind = sqlc.arg(resource_kind)
  AND resource_id = sqlc.arg(resource_id)
  AND expires_at > sqlc.arg(now)
ORDER BY source_ip
LIMIT 256;

-- name: ReadHTTPTemporaryBlock :one
SELECT *
FROM control.http_temporary_blocks
WHERE resource_kind = sqlc.arg(resource_kind)
  AND resource_id = sqlc.arg(resource_id)
  AND source_ip = sqlc.arg(source_ip);

-- name: CountHTTPTemporaryBlocks :one
SELECT count(*) FROM control.http_temporary_blocks
WHERE resource_kind = sqlc.arg(resource_kind)
  AND resource_id = sqlc.arg(resource_id);

-- name: StoreHTTPTemporaryBlock :exec
INSERT INTO control.http_temporary_blocks (
    resource_kind, resource_id, source_ip, expires_at, evidence_ended_at
) VALUES (
    sqlc.arg(resource_kind), sqlc.arg(resource_id), sqlc.arg(source_ip),
    sqlc.arg(expires_at), sqlc.arg(evidence_ended_at)
)
ON CONFLICT (resource_kind, resource_id, source_ip) DO UPDATE
SET expires_at = EXCLUDED.expires_at, evidence_ended_at = EXCLUDED.evidence_ended_at
WHERE control.http_temporary_blocks.expires_at <= sqlc.arg(evidence_started_at)
  AND control.http_temporary_blocks.evidence_ended_at < EXCLUDED.evidence_ended_at;

-- name: PruneHTTPTemporaryBlocks :exec
DELETE FROM control.http_temporary_blocks
WHERE (resource_kind, resource_id, source_ip) IN (
    SELECT expired.resource_kind, expired.resource_id, expired.source_ip
    FROM control.http_temporary_blocks AS expired
    WHERE expired.expires_at <= sqlc.arg(before)
    ORDER BY expired.expires_at
    LIMIT 1000
);

-- name: PruneHTTPResourceBlocks :exec
DELETE FROM control.http_temporary_blocks
WHERE resource_kind = sqlc.arg(resource_kind)
  AND resource_id = sqlc.arg(resource_id)
  AND expires_at <= sqlc.arg(before);
