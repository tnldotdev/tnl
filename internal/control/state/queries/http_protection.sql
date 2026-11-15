-- name: ListHTTPTemporaryBlocks :many
SELECT source_digest, expires_at
FROM control.http_temporary_blocks
WHERE service_id = sqlc.arg(service_id) AND expires_at > sqlc.arg(now)
ORDER BY source_digest LIMIT 256;

-- name: ReadHTTPTemporaryBlock :one
SELECT * FROM control.http_temporary_blocks
WHERE service_id = sqlc.arg(service_id) AND source_digest = sqlc.arg(source_digest);

-- name: CountHTTPTemporaryBlocks :one
SELECT count(*) FROM control.http_temporary_blocks
WHERE service_id = sqlc.arg(service_id);

-- name: StoreHTTPTemporaryBlock :exec
INSERT INTO control.http_temporary_blocks (service_id, source_digest, expires_at, evidence_ended_at)
VALUES (sqlc.arg(service_id), sqlc.arg(source_digest), sqlc.arg(expires_at), sqlc.arg(evidence_ended_at))
ON CONFLICT (service_id, source_digest) DO UPDATE
SET expires_at = EXCLUDED.expires_at, evidence_ended_at = EXCLUDED.evidence_ended_at
WHERE control.http_temporary_blocks.expires_at <= sqlc.arg(evidence_started_at)
  AND control.http_temporary_blocks.evidence_ended_at < EXCLUDED.evidence_ended_at;

-- name: PruneHTTPTemporaryBlocks :exec
DELETE FROM control.http_temporary_blocks
WHERE (service_id, source_digest) IN (
    SELECT expired.service_id, expired.source_digest FROM control.http_temporary_blocks AS expired
    WHERE expired.expires_at <= sqlc.arg(before)
    ORDER BY expired.expires_at LIMIT 1000
);

-- name: PruneHTTPResourceBlocks :exec
DELETE FROM control.http_temporary_blocks
WHERE service_id = sqlc.arg(service_id) AND expires_at <= sqlc.arg(before);
