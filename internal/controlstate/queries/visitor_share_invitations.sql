-- name: CreateVisitorShareInvitation :one
INSERT INTO control.visitor_share_invitations (
    id, team_id, public_url_id, normalized_email, token_digest, created_by_identity_id,
    idempotency_key, request_digest, created_at, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(team_id), sqlc.arg(public_url_id), sqlc.arg(normalized_email),
    sqlc.arg(token_digest), sqlc.arg(created_by_identity_id), sqlc.arg(idempotency_key),
    sqlc.arg(request_digest), sqlc.arg(created_at), sqlc.arg(expires_at)
)
ON CONFLICT (created_by_identity_id, idempotency_key) DO UPDATE
    SET id = control.visitor_share_invitations.id
RETURNING *;

-- name: GetVisitorShareInvitation :one
SELECT * FROM control.visitor_share_invitations WHERE id = sqlc.arg(id);

-- name: LockVisitorShareInvitation :one
SELECT * FROM control.visitor_share_invitations WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListVisitorShareInvitations :many
SELECT invitation.* FROM control.visitor_share_invitations AS invitation
JOIN control.public_urls AS url ON url.id = invitation.public_url_id AND url.team_id = invitation.team_id
JOIN control.team_memberships AS member ON member.team_id = invitation.team_id
    AND member.identity_id = sqlc.arg(identity_id) AND member.removed_at IS NULL
WHERE invitation.team_id = sqlc.arg(team_id)
    AND (sqlc.narg(cursor)::text IS NULL OR invitation.id > sqlc.narg(cursor))
    AND url.lifecycle_state <> 'deleted'
    AND ((url.public_url_scope = 'member' AND url.membership_id = member.id)
      OR (url.public_url_scope = 'shared' AND member.role IN ('admin', 'owner')))
ORDER BY invitation.id LIMIT 101;

-- name: LockVisitorInvitationRecipient :one
SELECT id, normalized_email, email_verified, disabled_at
FROM control.identities WHERE id = sqlc.arg(identity_id) FOR SHARE;

-- name: AcceptVisitorShareInvitation :one
UPDATE control.visitor_share_invitations
SET accepted_identity_id = sqlc.arg(identity_id), accepted_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > sqlc.arg(now)
RETURNING id;

-- name: InsertAcceptedVisitorGrant :exec
INSERT INTO control.visitor_access_grants (
    id, team_id, kind, public_url_id, identity_id, created_by_identity_id,
    idempotency_key, request_digest, created_at, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(team_id), 'identity_url', sqlc.arg(public_url_id),
    sqlc.arg(identity_id), sqlc.arg(created_by_identity_id), sqlc.arg(idempotency_key),
    sqlc.arg(request_digest), sqlc.arg(created_at), sqlc.arg(expires_at)
);

-- name: RevokeVisitorShareInvitation :exec
UPDATE control.visitor_share_invitations
SET revoked_at = sqlc.arg(now), revoked_by_identity_id = sqlc.arg(identity_id)
WHERE id = sqlc.arg(id) AND revoked_at IS NULL;

-- name: RevokeAcceptedVisitorGrant :exec
UPDATE control.visitor_access_grants
SET revoked_at = sqlc.arg(now), revoked_by_identity_id = sqlc.arg(identity_id)
WHERE id = sqlc.arg(id) AND kind = 'identity_url' AND revoked_at IS NULL;

-- name: ActiveIdentityURLVisitorGrant :one
SELECT EXISTS (
    SELECT 1 FROM control.visitor_access_grants AS access_grant
    WHERE access_grant.public_url_id = sqlc.arg(public_url_id)
      AND access_grant.identity_id = sqlc.arg(identity_id)
      AND access_grant.kind = 'identity_url' AND access_grant.revoked_at IS NULL
      AND access_grant.expires_at > sqlc.arg(now)::timestamptz
);
