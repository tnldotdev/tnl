-- name: LatestPublisherProvision :one
SELECT revision, document_ciphertext FROM publisher_provision_journal
WHERE server_origin = ? AND kind = ? AND binding_key = ?
ORDER BY revision DESC LIMIT 1;

-- name: AppendPublisherProvision :execrows
INSERT INTO publisher_provision_journal
    (server_origin, kind, binding_key, revision, document_ciphertext, created_at)
SELECT sqlc.arg(server_origin), sqlc.arg(kind), sqlc.arg(binding_key),
    sqlc.arg(previous_revision) + 1, sqlc.arg(document_ciphertext), sqlc.arg(created_at)
WHERE coalesce((SELECT max(revision) FROM publisher_provision_journal
    WHERE server_origin = sqlc.arg(server_origin) AND kind = sqlc.arg(kind)
    AND binding_key = sqlc.arg(binding_key)), 0) = sqlc.arg(previous_revision);
