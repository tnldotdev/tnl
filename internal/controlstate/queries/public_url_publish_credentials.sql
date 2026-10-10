-- name: InsertPublicURLPublishCredential :one
INSERT INTO control.public_url_publish_credentials (
    id, public_url_id, token_id, token_digest, issued_by_identity_id,
    membership_id, policy_revision, target, certificate_cache_key,
    certificate_scope, certificate_identifiers, certificate_challenge_method,
    created_at, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(public_url_id), sqlc.arg(token_id), sqlc.arg(token_digest),
    sqlc.arg(issued_by_identity_id), sqlc.arg(membership_id), sqlc.arg(policy_revision),
    sqlc.arg(target), sqlc.arg(certificate_cache_key), sqlc.arg(certificate_scope),
    sqlc.arg(certificate_identifiers), sqlc.arg(certificate_challenge_method),
    sqlc.arg(created_at), sqlc.arg(expires_at)
) RETURNING *;

-- name: GetPublicURLPublishCredentialByTokenID :one
SELECT * FROM control.public_url_publish_credentials WHERE token_id = sqlc.arg(token_id);

-- name: GetPublicURLPublishCredentialByID :one
SELECT * FROM control.public_url_publish_credentials WHERE id = sqlc.arg(id);

-- name: ListPublicURLPublishCredentials :many
SELECT * FROM control.public_url_publish_credentials
WHERE public_url_id = sqlc.arg(public_url_id)
ORDER BY created_at DESC, id;

-- name: RevokePublicURLPublishCredential :one
UPDATE control.public_url_publish_credentials
SET revoked_at = COALESCE(revoked_at, sqlc.arg(revoked_at))
WHERE id = sqlc.arg(id) AND public_url_id = sqlc.arg(public_url_id)
RETURNING *;

-- name: AttachPublishRunCredential :execrows
INSERT INTO control.publish_run_publish_credentials (publish_run_id, public_url_id, credential_id)
SELECT sqlc.arg(publish_run_id), sqlc.arg(public_url_id), credentials.id
FROM control.public_url_publish_credentials AS credentials
WHERE credentials.id = sqlc.arg(credential_id) AND credentials.public_url_id = sqlc.arg(public_url_id);

-- name: GetPublishRunCredentialState :one
SELECT credentials.id, credentials.revoked_at, credentials.expires_at,
    credentials.membership_id, credentials.issued_by_identity_id,
    credentials.policy_revision, credentials.target, credentials.public_url_id
FROM control.publish_run_publish_credentials AS runs
JOIN control.public_url_publish_credentials AS credentials ON credentials.id = runs.credential_id
WHERE runs.publish_run_id = sqlc.arg(publish_run_id);
