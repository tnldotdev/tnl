-- name: CreateTeamURLVisitorGrant :one
INSERT INTO control.visitor_access_grants (
    id, team_id, kind, public_url_id, created_by_identity_id,
    idempotency_key, request_digest, created_at, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(team_id), 'team_url', sqlc.arg(public_url_id),
    sqlc.arg(created_by_identity_id), sqlc.arg(idempotency_key), sqlc.arg(request_digest),
    sqlc.arg(created_at), sqlc.narg(expires_at)
)
ON CONFLICT (created_by_identity_id, idempotency_key) DO UPDATE
    SET id = control.visitor_access_grants.id
RETURNING *;

-- name: GetTeamURLVisitorGrant :one
SELECT * FROM control.visitor_access_grants
WHERE id = sqlc.arg(id) AND kind = 'team_url';

-- name: LockTeamURLVisitorGrant :one
SELECT * FROM control.visitor_access_grants
WHERE id = sqlc.arg(id) AND kind = 'team_url'
FOR UPDATE;

-- name: ListTeamURLVisitorGrants :many
SELECT access_grant.* FROM control.visitor_access_grants AS access_grant
JOIN control.public_urls AS url ON url.id = access_grant.public_url_id AND url.team_id = access_grant.team_id
JOIN control.team_memberships AS member ON member.team_id = access_grant.team_id
    AND member.identity_id = sqlc.arg(identity_id) AND member.removed_at IS NULL
WHERE access_grant.team_id = sqlc.arg(team_id) AND access_grant.kind = 'team_url'
    AND (sqlc.narg(cursor)::text IS NULL OR access_grant.id > sqlc.narg(cursor))
    AND url.lifecycle_state <> 'deleted'
    AND ((url.public_url_scope = 'member' AND url.membership_id = member.id)
      OR (url.public_url_scope = 'shared' AND member.role IN ('admin', 'owner')))
ORDER BY access_grant.id LIMIT 101;

-- name: RevokeTeamURLVisitorGrant :exec
UPDATE control.visitor_access_grants
SET revoked_at = sqlc.arg(now), revoked_by_identity_id = sqlc.arg(identity_id)
WHERE id = sqlc.arg(id) AND kind = 'team_url' AND revoked_at IS NULL;

-- name: ActiveTeamURLVisitorGrant :one
SELECT EXISTS (
    SELECT 1 FROM control.visitor_access_grants AS access_grant
    WHERE access_grant.team_id = sqlc.arg(team_id) AND access_grant.public_url_id = sqlc.arg(public_url_id)
      AND access_grant.kind = 'team_url' AND access_grant.revoked_at IS NULL
      AND (access_grant.expires_at IS NULL OR access_grant.expires_at > sqlc.arg(now)::timestamptz)
);
