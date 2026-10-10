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

-- name: InsertEphemeralPublishCredential :one
INSERT INTO control.public_url_publish_credentials (
    id, kind, token_id, token_digest, issued_by_identity_id, membership_id,
    policy_revision, target, team_id, domain_id, namespace, issued_role,
    certificate_cache_key, certificate_scope, certificate_identifiers,
    certificate_challenge_method, created_at, expires_at
) VALUES (
    sqlc.arg(id), 'ephemeral', sqlc.arg(token_id), sqlc.arg(token_digest),
    sqlc.arg(issued_by_identity_id), sqlc.arg(membership_id), sqlc.arg(policy_revision),
    '', sqlc.arg(team_id), sqlc.arg(domain_id), sqlc.arg(namespace), sqlc.arg(issued_role),
    sqlc.arg(certificate_cache_key), sqlc.arg(certificate_scope),
    sqlc.arg(certificate_identifiers), 'dns-01', sqlc.arg(created_at), sqlc.arg(expires_at)
) RETURNING *;

-- name: GetReadyEphemeralCredentialDomain :one
SELECT id, canonical_domain, kind, dns_authority_reference
FROM control.domains
WHERE id = sqlc.arg(domain_id) AND state = 'ready' AND released_at IS NULL
    AND (kind = 'managed' OR team_id = sqlc.arg(team_id))
FOR SHARE;

-- name: GetPublicURLPublishCredentialByTokenID :one
SELECT * FROM control.public_url_publish_credentials WHERE token_id = sqlc.arg(token_id);

-- name: GetPublicURLPublishCredentialByID :one
SELECT * FROM control.public_url_publish_credentials WHERE id = sqlc.arg(id);

-- name: ListPublicURLPublishCredentials :many
SELECT * FROM control.public_url_publish_credentials
WHERE public_url_id = sqlc.arg(public_url_id)
ORDER BY created_at DESC, id;

-- name: ListTeamPublicURLPublishCredentials :many
SELECT credentials.id, credentials.kind, COALESCE(credentials.public_url_id, '') AS public_url_id,
    credentials.created_at, credentials.expires_at, credentials.revoked_at,
    COALESCE(routes.canonical_hostname, '') AS canonical_hostname,
    routes.public_port,
    COALESCE(credentials.team_id, routes.team_id) AS team_id,
    COALESCE(credentials.domain_id, routes.domain_id) AS domain_id,
    COALESCE(credentials.namespace, '') AS namespace
FROM control.public_url_publish_credentials AS credentials
LEFT JOIN control.public_urls AS routes ON routes.id = credentials.public_url_id
WHERE ((credentials.kind = 'saved_url' AND routes.team_id = sqlc.arg(team_id) AND routes.lifecycle_state <> 'deleted')
    OR (credentials.kind = 'ephemeral' AND credentials.team_id = sqlc.arg(team_id)))
    AND (sqlc.narg(cursor)::text IS NULL OR credentials.id > sqlc.narg(cursor))
ORDER BY credentials.id
LIMIT 101;

-- name: RevokePublicURLPublishCredential :one
UPDATE control.public_url_publish_credentials
SET revoked_at = COALESCE(revoked_at, sqlc.arg(revoked_at))
WHERE id = sqlc.arg(id) AND public_url_id = sqlc.arg(public_url_id)
RETURNING *;

-- name: RevokeEphemeralPublishCredential :one
UPDATE control.public_url_publish_credentials
SET revoked_at = COALESCE(revoked_at, sqlc.arg(revoked_at))
WHERE id = sqlc.arg(id) AND kind = 'ephemeral' AND team_id = sqlc.arg(team_id)
RETURNING *;

-- name: AttachPublishRunCredential :execrows
INSERT INTO control.publish_run_publish_credentials (publish_run_id, public_url_id, credential_id)
SELECT sqlc.arg(publish_run_id), sqlc.arg(public_url_id), credentials.id
FROM control.public_url_publish_credentials AS credentials
LEFT JOIN control.ephemeral_public_url_allocations AS allocations
    ON allocations.credential_id = credentials.id AND allocations.public_url_id = sqlc.arg(public_url_id)
WHERE credentials.id = sqlc.arg(credential_id)
    AND ((credentials.kind = 'saved_url' AND credentials.public_url_id = sqlc.arg(public_url_id))
        OR (credentials.kind = 'ephemeral' AND allocations.public_url_id = sqlc.arg(public_url_id)));

-- name: GetPublishRunCredentialState :one
SELECT credentials.id, credentials.kind, credentials.revoked_at, credentials.expires_at,
    credentials.membership_id, credentials.issued_by_identity_id,
    credentials.policy_revision, credentials.target, credentials.public_url_id,
    credentials.team_id, credentials.domain_id, credentials.namespace, credentials.issued_role,
    COALESCE(allocations.credential_id, '') AS allocation_credential_id
FROM control.publish_run_publish_credentials AS runs
JOIN control.public_url_publish_credentials AS credentials ON credentials.id = runs.credential_id
LEFT JOIN control.ephemeral_public_url_allocations AS allocations ON allocations.public_url_id = runs.public_url_id
WHERE runs.publish_run_id = sqlc.arg(publish_run_id);
