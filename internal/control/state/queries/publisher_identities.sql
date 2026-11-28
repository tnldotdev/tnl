-- name: LockPublisherIdentity :one
SELECT * FROM control.publisher_identities WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ReadPublisherIdentity :one
SELECT * FROM control.publisher_identities WHERE id = sqlc.arg(id);

-- name: ReadPublisherGrant :one
SELECT * FROM control.publisher_grants WHERE id = sqlc.arg(id) AND publisher_identity_id = sqlc.arg(publisher_identity_id);

-- name: InsertPublisherIdentity :one
INSERT INTO control.publisher_identities(id, team_id, name, kind, created_by_identity_id, guest_id, created_at, ownership, owner_membership_id)
VALUES (sqlc.arg(id), sqlc.narg(team_id), sqlc.arg(name), sqlc.arg(kind), sqlc.narg(created_by_identity_id), sqlc.narg(guest_id), sqlc.arg(created_at), sqlc.arg(ownership), sqlc.narg(owner_membership_id)) RETURNING *;

-- name: InsertPublisherKey :exec
INSERT INTO control.publisher_identity_keys(id, publisher_identity_id, public_key, revision, created_at)
VALUES (sqlc.arg(id), sqlc.arg(publisher_identity_id), sqlc.arg(public_key), sqlc.arg(revision), sqlc.arg(created_at));

-- name: GetPublisherKey :one
SELECT * FROM control.publisher_identity_keys WHERE id = sqlc.arg(id) AND publisher_identity_id = sqlc.arg(publisher_identity_id);

-- name: RetirePublisherKey :execrows
UPDATE control.publisher_identity_keys SET retired_at = sqlc.arg(now) WHERE id = sqlc.arg(id) AND retired_at IS NULL;

-- name: InsertPublisherGrant :one
INSERT INTO control.publisher_grants(id, publisher_identity_id, team_id, guest_id, created_by_identity_id, kind, service_id, domain_id, namespace, membership_id, namespace_scope, protocols, created_at, expires_at)
SELECT sqlc.arg(id),publisher.id,publisher.team_id,publisher.guest_id,sqlc.narg(created_by_identity_id),
    sqlc.arg(kind),sqlc.narg(service_id),sqlc.narg(domain_id),sqlc.narg(namespace),
    sqlc.narg(membership_id),sqlc.narg(namespace_scope),sqlc.narg(protocols)::text[],sqlc.arg(created_at),sqlc.narg(expires_at)
FROM control.publisher_identities publisher WHERE publisher.id=sqlc.arg(publisher_identity_id)
RETURNING *;

-- name: GetPublisherGrant :one
SELECT * FROM control.publisher_grants WHERE id = sqlc.arg(id) AND publisher_identity_id = sqlc.arg(publisher_identity_id) FOR SHARE;

-- name: RevokePublisherGrant :execrows
UPDATE control.publisher_grants SET revoked_at = COALESCE(revoked_at, sqlc.arg(now)) WHERE id = sqlc.arg(id) AND publisher_identity_id = sqlc.arg(publisher_identity_id);

-- name: RevokePublisherIdentity :execrows
UPDATE control.publisher_identities SET revoked_at = COALESCE(revoked_at, sqlc.arg(now)) WHERE id = sqlc.arg(id) AND team_id = sqlc.arg(team_id);

-- name: InsertPublisherEnrollment :one
INSERT INTO control.publisher_enrollments(id, enrollment_key_digest, team_id, name, identity_kind, grant_kind, service_id, domain_id, namespace, membership_id, namespace_scope, protocols, created_by_identity_id, created_at, expires_at, ownership, owner_membership_id)
VALUES (sqlc.arg(id), sqlc.arg(enrollment_key_digest), sqlc.arg(team_id), sqlc.arg(name), sqlc.arg(identity_kind), sqlc.arg(grant_kind), sqlc.narg(service_id), sqlc.narg(domain_id), sqlc.narg(namespace), sqlc.narg(membership_id), sqlc.narg(namespace_scope), sqlc.narg(protocols)::text[], sqlc.arg(created_by_identity_id), sqlc.arg(created_at), sqlc.arg(expires_at), sqlc.arg(ownership), sqlc.narg(owner_membership_id)) RETURNING *;

-- name: LockPublisherEnrollment :one
SELECT * FROM control.publisher_enrollments WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: RedeemPublisherEnrollment :exec
UPDATE control.publisher_enrollments SET redeemed_identity_id = sqlc.arg(identity_id), redeemed_key_id = sqlc.arg(key_id), redeemed_grant_id = sqlc.arg(grant_id), redeemed_public_key = sqlc.arg(public_key), redeemed_at = sqlc.arg(now) WHERE id = sqlc.arg(id);

-- name: ClaimPublisherAssertion :execrows
INSERT INTO control.publisher_assertions(publisher_identity_id, assertion_id, expires_at)
VALUES (sqlc.arg(publisher_identity_id), sqlc.arg(assertion_id), sqlc.arg(expires_at))
ON CONFLICT DO NOTHING;

-- name: InsertPublisherAccess :exec
INSERT INTO control.publisher_access_tokens(access_token_digest, publisher_identity_id, grant_id, key_id, created_at, expires_at)
VALUES (sqlc.arg(access_token_digest), sqlc.arg(publisher_identity_id), sqlc.arg(grant_id), sqlc.arg(key_id), sqlc.arg(created_at), sqlc.arg(expires_at));

-- name: GetPublisherAccess :one
SELECT * FROM control.publisher_access_tokens WHERE access_token_digest = sqlc.arg(access_token_digest);

-- name: GetPublisherDomain :one
-- publisher checks may already hold a service lock. never acquire a domain lock
-- afterward: authority mutations hold team -> domain -> service. a snapshot read
-- permits the heartbeat to commit before a waiting release closes its run.
SELECT * FROM control.domains WHERE id = sqlc.arg(id) AND state = 'ready' AND released_at IS NULL AND (kind = 'managed' OR team_id = sqlc.arg(team_id));

-- name: InsertPublisherAllocation :exec
INSERT INTO control.publisher_namespace_allocations(service_id, publisher_identity_id, publisher_grant_id, invocation_id, deployment_id, required_temporary_approval, requested_expires_at)
VALUES (sqlc.arg(service_id), sqlc.arg(publisher_identity_id), sqlc.arg(publisher_grant_id), sqlc.arg(invocation_id), sqlc.narg(deployment_id), sqlc.arg(required_temporary_approval), sqlc.narg(requested_expires_at));

-- name: GetPublisherAllocation :one
SELECT * FROM control.publisher_namespace_allocations WHERE service_id = sqlc.arg(service_id);

-- name: FindPublisherAllocation :one
SELECT * FROM control.publisher_namespace_allocations
WHERE publisher_identity_id=sqlc.arg(publisher_identity_id)
AND publisher_grant_id=sqlc.arg(publisher_grant_id) AND invocation_id=sqlc.arg(invocation_id);

-- name: ListPublisherIdentities :many
SELECT * FROM control.publisher_identities WHERE team_id = sqlc.arg(team_id) AND id > sqlc.arg(after_id) ORDER BY id LIMIT 101;

-- name: ListPublisherGrants :many
SELECT * FROM control.publisher_grants WHERE publisher_identity_id = sqlc.arg(publisher_identity_id) ORDER BY id;

-- name: PublisherScopeAvailable :one
-- this read does not lock resources after identities. service run
-- transactions lock their saved service first and recheck the grant.
SELECT EXISTS (
    SELECT 1 FROM control.publisher_grants g
    JOIN control.publisher_identities p ON p.id = g.publisher_identity_id
    LEFT JOIN control.services s ON s.id = g.service_id
    LEFT JOIN control.domains d ON d.id = COALESCE(g.domain_id, s.domain_id)
    WHERE p.id = sqlc.arg(publisher_identity_id) AND g.id = sqlc.arg(grant_id)
      AND (p.ownership <> 'member' OR control.active_membership(p.owner_membership_id, sqlc.arg(now)))
      AND (p.kind = 'guest' OR EXISTS (SELECT 1 FROM control.teams t WHERE t.id = p.team_id AND t.deleted_at IS NULL))
      AND ((g.kind = 'deployment_credential' AND p.kind <> 'guest' AND EXISTS (
                SELECT 1 FROM control.deployment_management_grants approval
                WHERE approval.grant_id=g.id AND approval.team_id=p.team_id
                AND control.deployment_credential_available(g.id))) OR
           (g.kind = 'service' AND EXISTS(
               SELECT 1 FROM control.publisher_service_permission(p.id,g.id,s.id,sqlc.arg(now)))) OR
           (g.kind = 'namespace' AND p.kind <> 'guest' AND d.state = 'ready' AND d.released_at IS NULL
            AND (d.kind = 'managed' OR d.team_id = p.team_id)))
)::boolean;
