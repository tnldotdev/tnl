-- name: CreatePublisherEnrollment :one
INSERT INTO control.publisher_enrollment_keys (
    id, token_digest, team_id, name, identity_kind, grant_kind, public_url_id,
    domain_id, namespace, created_by_identity_id, created_at, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(token_digest), sqlc.arg(team_id), sqlc.arg(name),
    sqlc.arg(identity_kind), sqlc.arg(grant_kind), sqlc.narg(public_url_id),
    sqlc.narg(domain_id), sqlc.narg(namespace), sqlc.arg(created_by_identity_id),
    sqlc.arg(created_at), sqlc.arg(expires_at)
) RETURNING *;

-- name: LockPublisherEnrollment :one
SELECT * FROM control.publisher_enrollment_keys WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: LockPublisherIdentity :one
SELECT * FROM control.publisher_identities WHERE id = sqlc.arg(id) FOR SHARE;

-- name: LockPublisherIdentityForRotation :one
SELECT * FROM control.publisher_identities WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: GetPublisherGrantURL :one
SELECT id, team_id, lifecycle_state, purpose, ephemeral, public_url_scope, membership_id
FROM control.public_urls WHERE id = sqlc.arg(public_url_id);

-- name: RedeemPublisherEnrollment :execrows
UPDATE control.publisher_enrollment_keys
SET redeemed_identity_id = sqlc.arg(publisher_identity_id),
    redeemed_key_id = sqlc.arg(key_id), redeemed_grant_id = sqlc.arg(grant_id),
    redeemed_public_key = sqlc.arg(public_key), redeemed_at = sqlc.arg(redeemed_at)
WHERE id = sqlc.arg(id) AND redeemed_at IS NULL;

-- name: InsertPublisherIdentity :one
INSERT INTO control.publisher_identities (
    id, team_id, name, kind, created_by_identity_id, created_at
) VALUES (
    sqlc.arg(id), sqlc.arg(team_id), sqlc.arg(name), sqlc.arg(kind),
    sqlc.narg(created_by_identity_id), sqlc.arg(created_at)
) RETURNING *;

-- name: InsertPublisherIdentityKey :one
INSERT INTO control.publisher_identity_keys (
    id, publisher_identity_id, revision, public_key, created_at
) VALUES (
    sqlc.arg(id), sqlc.arg(publisher_identity_id), sqlc.arg(revision),
    sqlc.arg(public_key), sqlc.arg(created_at)
) RETURNING *;

-- name: InsertPublisherIdentityGrant :one
INSERT INTO control.publisher_identity_grants (
    id, publisher_identity_id, kind, public_url_id, domain_id, namespace,
    created_at, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(publisher_identity_id), sqlc.arg(kind),
    sqlc.narg(public_url_id), sqlc.narg(domain_id), sqlc.narg(namespace),
    sqlc.arg(created_at), sqlc.narg(expires_at)
) RETURNING *;

-- name: GetPublisherIdentityKey :one
SELECT keys.*, identities.team_id, identities.revoked_at AS identity_revoked_at
FROM control.publisher_identity_keys AS keys
JOIN control.publisher_identities AS identities ON identities.id = keys.publisher_identity_id
WHERE keys.id = sqlc.arg(key_id) AND keys.publisher_identity_id = sqlc.arg(publisher_identity_id);

-- name: GetPublisherIdentityGrant :one
SELECT grants.*, identities.team_id, identities.revoked_at AS identity_revoked_at
FROM control.publisher_identity_grants AS grants
JOIN control.publisher_identities AS identities ON identities.id = grants.publisher_identity_id
WHERE grants.id = sqlc.arg(grant_id) AND grants.publisher_identity_id = sqlc.arg(publisher_identity_id)
FOR SHARE OF grants;

-- name: ListPublisherIdentityManagementGrants :many
SELECT identities.team_id, grants.id AS grant_id, grants.kind, grants.public_url_id,
    routes.membership_id AS public_url_membership_id
FROM control.publisher_identities AS identities
JOIN control.publisher_identity_grants AS grants ON grants.publisher_identity_id = identities.id
LEFT JOIN control.public_urls AS routes ON routes.id = grants.public_url_id
WHERE identities.id = sqlc.arg(publisher_identity_id) AND identities.team_id = sqlc.arg(team_id)
ORDER BY grants.id;

-- name: DeleteExpiredPublisherAssertions :exec
DELETE FROM control.publisher_assertions WHERE expires_at <= sqlc.arg(now);

-- name: ClaimPublisherAssertion :execrows
INSERT INTO control.publisher_assertions (publisher_identity_id, assertion_id, expires_at)
VALUES (sqlc.arg(publisher_identity_id), sqlc.arg(assertion_id), sqlc.arg(expires_at))
ON CONFLICT DO NOTHING;

-- name: InsertPublisherAccessToken :exec
INSERT INTO control.publisher_access_tokens (
    digest, publisher_identity_id, grant_id, key_id, created_at, expires_at
) VALUES (
    sqlc.arg(digest), sqlc.arg(publisher_identity_id), sqlc.arg(grant_id), sqlc.arg(key_id),
    sqlc.arg(created_at), sqlc.arg(expires_at)
);

-- name: GetPublisherAccessToken :one
SELECT tokens.*, grants.kind, grants.public_url_id, grants.domain_id,
    grants.namespace, grants.expires_at AS grant_expires_at,
    grants.revoked_at AS grant_revoked_at, identities.team_id,
    identities.revoked_at AS identity_revoked_at
FROM control.publisher_access_tokens AS tokens
JOIN control.publisher_identity_grants AS grants ON grants.id = tokens.grant_id
JOIN control.publisher_identities AS identities ON identities.id = tokens.publisher_identity_id
WHERE tokens.digest = sqlc.arg(digest);

-- name: DeleteExpiredPublisherAccessTokens :exec
DELETE FROM control.publisher_access_tokens WHERE expires_at <= sqlc.arg(now);

-- name: RetirePublisherIdentityKey :execrows
UPDATE control.publisher_identity_keys SET retired_at = sqlc.arg(retired_at)
WHERE id = sqlc.arg(id) AND publisher_identity_id = sqlc.arg(publisher_identity_id)
    AND retired_at IS NULL;

-- name: NextPublisherIdentityKeyRevision :one
SELECT COALESCE(MAX(revision), 0)::bigint + 1
FROM control.publisher_identity_keys WHERE publisher_identity_id = sqlc.arg(publisher_identity_id);

-- name: RevokePublisherIdentity :one
UPDATE control.publisher_identities SET revoked_at = COALESCE(revoked_at, sqlc.arg(revoked_at))
WHERE id = sqlc.arg(id) AND team_id = sqlc.arg(team_id)
RETURNING *;

-- name: RevokePublisherIdentityGrant :execrows
UPDATE control.publisher_identity_grants AS grants SET revoked_at = COALESCE(grants.revoked_at, sqlc.arg(revoked_at))
WHERE grants.id = sqlc.arg(id) AND grants.publisher_identity_id = sqlc.arg(publisher_identity_id)
    AND EXISTS (SELECT 1 FROM control.publisher_identities AS identities
        WHERE identities.id = sqlc.arg(publisher_identity_id) AND identities.team_id = sqlc.arg(team_id));

-- name: AttachPublishRunIdentity :execrows
INSERT INTO control.publish_run_publisher_identities (
    publish_run_id, public_url_id, publisher_identity_id, publisher_grant_id, created_at
)
SELECT runs.id, runs.public_url_id, sqlc.arg(publisher_identity_id),
    sqlc.arg(grant_id), sqlc.arg(created_at)
FROM control.publish_runs AS runs
WHERE runs.id = sqlc.arg(publish_run_id) AND runs.public_url_id = sqlc.arg(public_url_id)
    AND runs.closed_at IS NULL
ON CONFLICT (publish_run_id) DO NOTHING;

-- name: GetPublishRunPublisherIdentity :one
SELECT identities.id, identities.team_id, identities.revoked_at, grants.kind, grants.public_url_id,
    grants.domain_id, grants.namespace, grants.revoked_at AS grant_revoked_at,
    grants.expires_at AS grant_expires_at
FROM control.publish_run_publisher_identities AS runs
JOIN control.publisher_identities AS identities ON identities.id = runs.publisher_identity_id
JOIN control.publisher_identity_grants AS grants
    ON grants.publisher_identity_id = identities.id AND grants.id = runs.publisher_grant_id
WHERE runs.publish_run_id = sqlc.arg(publish_run_id);
