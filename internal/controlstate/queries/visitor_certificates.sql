-- name: DatabaseVisitorAllowed :one
SELECT
    EXISTS (
        SELECT 1 FROM control.team_memberships AS member
        WHERE member.team_id = url.team_id AND member.identity_id = sqlc.arg(identity_id)
          AND member.removed_at IS NULL
          AND ((url.public_url_scope = 'member' AND url.membership_id = member.id)
               OR (url.public_url_scope = 'shared' AND member.role IN ('owner', 'admin')))
    ) OR EXISTS (
        SELECT 1 FROM control.visitor_access_grants AS access_grant
        WHERE access_grant.public_url_id = url.id AND access_grant.kind = 'identity_url'
          AND access_grant.identity_id = sqlc.arg(identity_id)
          AND access_grant.revoked_at IS NULL
          AND (access_grant.expires_at IS NULL OR access_grant.expires_at > sqlc.arg(now)::timestamptz)
    ) OR EXISTS (
        SELECT 1 FROM control.visitor_access_grants AS access_grant
        JOIN control.team_memberships AS member ON member.team_id = access_grant.team_id
          AND member.identity_id = sqlc.arg(identity_id) AND member.removed_at IS NULL
        WHERE access_grant.team_id = url.team_id AND access_grant.public_url_id = url.id
          AND access_grant.kind = 'team_url' AND access_grant.revoked_at IS NULL
          AND (access_grant.expires_at IS NULL OR access_grant.expires_at > sqlc.arg(now)::timestamptz)
    ) AS allowed
FROM control.public_urls AS url
JOIN control.teams AS team ON team.id = url.team_id AND team.deleted_at IS NULL
JOIN control.identities AS identity ON identity.id = sqlc.arg(identity_id) AND identity.disabled_at IS NULL
WHERE url.id = sqlc.arg(public_url_id) AND url.lifecycle_state = 'enabled'
  AND url.purpose = 'app' AND url.service_protocol IN ('postgres', 'mysql', 'redis');
