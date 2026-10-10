-- name: InsertEphemeralPublicURLAllocation :execrows
INSERT INTO control.ephemeral_public_url_allocations (public_url_id, credential_id, invocation_id)
SELECT sqlc.arg(public_url_id), credentials.id, sqlc.arg(invocation_id)
FROM control.public_url_publish_credentials AS credentials
WHERE credentials.id = sqlc.arg(credential_id) AND credentials.kind = 'ephemeral';

-- name: GetEphemeralPublicURLAllocation :one
SELECT public_url_id, credential_id, invocation_id
FROM control.ephemeral_public_url_allocations
WHERE public_url_id = sqlc.arg(public_url_id);
