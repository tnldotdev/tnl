-- name: LockPublisherIdentity :one
SELECT * FROM control.publisher_identities WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: InsertPublisherIdentity :one
INSERT INTO control.publisher_identities(id, team_id, name, kind, created_by_identity_id, guest_id, created_at)
VALUES (sqlc.arg(id), sqlc.arg(team_id), sqlc.arg(name), sqlc.arg(kind), sqlc.arg(created_by_identity_id), sqlc.narg(guest_id), sqlc.arg(created_at)) RETURNING *;

-- name: InsertPublisherKey :exec
INSERT INTO control.publisher_identity_keys(id, publisher_identity_id, public_key, revision, created_at)
VALUES (sqlc.arg(id), sqlc.arg(publisher_identity_id), sqlc.arg(public_key), sqlc.arg(revision), sqlc.arg(created_at));

-- name: GetPublisherKey :one
SELECT * FROM control.publisher_identity_keys WHERE id = sqlc.arg(id) AND publisher_identity_id = sqlc.arg(publisher_identity_id);

-- name: RetirePublisherKey :execrows
UPDATE control.publisher_identity_keys SET retired_at = sqlc.arg(now) WHERE id = sqlc.arg(id) AND retired_at IS NULL;

-- name: InsertPublisherGrant :one
INSERT INTO control.publisher_grants(id, publisher_identity_id, created_by_identity_id, kind, public_url_id, domain_id, namespace, membership_id, public_url_scope, created_at, expires_at)
VALUES (sqlc.arg(id), sqlc.arg(publisher_identity_id), sqlc.arg(created_by_identity_id), sqlc.arg(kind), sqlc.narg(public_url_id), sqlc.narg(domain_id), sqlc.narg(namespace), sqlc.narg(membership_id), sqlc.narg(public_url_scope), sqlc.arg(created_at), sqlc.narg(expires_at)) RETURNING *;

-- name: GetPublisherGrant :one
SELECT * FROM control.publisher_grants WHERE id = sqlc.arg(id) AND publisher_identity_id = sqlc.arg(publisher_identity_id) FOR SHARE;

-- name: RevokePublisherGrant :execrows
UPDATE control.publisher_grants SET revoked_at = COALESCE(revoked_at, sqlc.arg(now)) WHERE id = sqlc.arg(id) AND publisher_identity_id = sqlc.arg(publisher_identity_id);

-- name: RevokePublisherIdentity :execrows
UPDATE control.publisher_identities SET revoked_at = COALESCE(revoked_at, sqlc.arg(now)) WHERE id = sqlc.arg(id) AND team_id = sqlc.arg(team_id);

-- name: InsertPublisherEnrollment :one
INSERT INTO control.publisher_enrollments(id, enrollment_key_digest, team_id, name, identity_kind, grant_kind, public_url_id, domain_id, namespace, membership_id, public_url_scope, created_by_identity_id, created_at, expires_at)
VALUES (sqlc.arg(id), sqlc.arg(enrollment_key_digest), sqlc.arg(team_id), sqlc.arg(name), sqlc.arg(identity_kind), sqlc.arg(grant_kind), sqlc.narg(public_url_id), sqlc.narg(domain_id), sqlc.narg(namespace), sqlc.narg(membership_id), sqlc.narg(public_url_scope), sqlc.arg(created_by_identity_id), sqlc.arg(created_at), sqlc.arg(expires_at)) RETURNING *;

-- name: LockPublisherEnrollment :one
SELECT * FROM control.publisher_enrollments WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: RedeemPublisherEnrollment :exec
UPDATE control.publisher_enrollments SET redeemed_identity_id = sqlc.arg(identity_id), redeemed_key_id = sqlc.arg(key_id), redeemed_grant_id = sqlc.arg(grant_id), redeemed_public_key = sqlc.arg(public_key), redeemed_at = sqlc.arg(now) WHERE id = sqlc.arg(id);

-- name: PrunePublisherAssertions :exec
DELETE FROM control.publisher_assertions WHERE publisher_identity_id = sqlc.arg(publisher_identity_id) AND expires_at <= sqlc.arg(now);

-- name: ClaimPublisherAssertion :execrows
INSERT INTO control.publisher_assertions(publisher_identity_id, assertion_id, expires_at)
SELECT sqlc.arg(publisher_identity_id), sqlc.arg(assertion_id), sqlc.arg(expires_at)
WHERE (SELECT count(*) FROM control.publisher_assertions WHERE publisher_identity_id = sqlc.arg(publisher_identity_id)) < 256
ON CONFLICT DO NOTHING;

-- name: PrunePublisherAccess :exec
DELETE FROM control.publisher_access_tokens WHERE publisher_identity_id = sqlc.arg(publisher_identity_id) AND expires_at <= sqlc.arg(now);

-- name: InsertPublisherAccess :exec
INSERT INTO control.publisher_access_tokens(access_token_digest, publisher_identity_id, grant_id, key_id, created_at, expires_at)
VALUES (sqlc.arg(access_token_digest), sqlc.arg(publisher_identity_id), sqlc.arg(grant_id), sqlc.arg(key_id), sqlc.arg(created_at), sqlc.arg(expires_at));

-- name: GetPublisherAccess :one
SELECT * FROM control.publisher_access_tokens WHERE access_token_digest = sqlc.arg(access_token_digest);

-- name: GetPublisherDomain :one
-- publisher checks may already hold a URL lock. never acquire a domain lock
-- afterward: authority mutations hold team -> domain -> URL. a snapshot read
-- permits the heartbeat to commit before a waiting release closes its run.
SELECT * FROM control.domains WHERE id = sqlc.arg(id) AND state = 'ready' AND released_at IS NULL AND (kind = 'managed' OR team_id = sqlc.arg(team_id));

-- name: AttachPublisherRun :exec
INSERT INTO control.publish_run_publisher_grants(publish_run_id, publisher_identity_id, publisher_grant_id)
VALUES (sqlc.arg(publish_run_id), sqlc.arg(publisher_identity_id), sqlc.arg(publisher_grant_id));

-- name: GetPublisherRun :one
SELECT * FROM control.publish_run_publisher_grants WHERE publish_run_id = sqlc.arg(publish_run_id);

-- name: InsertPublisherAllocation :exec
INSERT INTO control.publisher_namespace_allocations(public_url_id, publisher_identity_id, publisher_grant_id, invocation_id)
VALUES (sqlc.arg(public_url_id), sqlc.arg(publisher_identity_id), sqlc.arg(publisher_grant_id), sqlc.arg(invocation_id));

-- name: GetPublisherAllocation :one
SELECT * FROM control.publisher_namespace_allocations WHERE public_url_id = sqlc.arg(public_url_id);

-- name: ListPublisherIdentities :many
SELECT * FROM control.publisher_identities WHERE team_id = sqlc.arg(team_id) AND id > sqlc.arg(after_id) ORDER BY id LIMIT 101;

-- name: ListPublisherGrants :many
SELECT * FROM control.publisher_grants WHERE publisher_identity_id = sqlc.arg(publisher_identity_id) ORDER BY id;

-- name: PublisherScopeAvailable :one
-- this read does not lock URLs after identities. URL/run transactions acquire
-- their URL lock first and recheck the same live grant before committing.
SELECT EXISTS (
    SELECT 1 FROM control.publisher_grants g
    JOIN control.publisher_identities p ON p.id = g.publisher_identity_id
    LEFT JOIN control.public_urls u ON u.id = g.public_url_id
    LEFT JOIN control.domains d ON d.id = COALESCE(g.domain_id, u.domain_id)
    WHERE p.id = sqlc.arg(publisher_identity_id) AND g.id = sqlc.arg(grant_id)
      AND (p.kind = 'guest' OR EXISTS (SELECT 1 FROM control.teams t WHERE t.id = p.team_id AND t.deleted_at IS NULL))
      AND d.state = 'ready' AND d.released_at IS NULL AND (d.kind = 'managed' OR d.team_id = p.team_id)
      AND ((g.kind = 'namespace' AND p.kind <> 'guest') OR
          (g.kind = 'saved_url' AND u.team_id = p.team_id AND u.lifecycle_state = 'enabled'
           AND ((p.kind <> 'guest' AND NOT u.ephemeral AND u.purpose IN ('app', 'alias', 'demo', 'oauth', 'webhooks')) OR
                (p.kind = 'guest' AND u.purpose = 'demo' AND EXISTS (
                    SELECT 1 FROM control.guest_public_urls gu WHERE gu.guest_id = p.guest_id AND gu.public_url_id = u.id)))))
)::boolean;
