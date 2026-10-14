-- name: ListVisitorAccessInventory :many
WITH available AS (
    SELECT url.id, url.team_id, team.display_name AS team_name, url.canonical_hostname, url.service_protocol,
        url.public_port, url.public_url_scope, url.purpose, url.lifecycle_state,
        EXISTS (
            SELECT 1 FROM control.team_memberships AS member
            WHERE member.team_id = url.team_id AND member.identity_id = sqlc.arg(identity_id)
              AND member.removed_at IS NULL
        ) AS member,
        EXISTS (
            SELECT 1 FROM control.team_memberships AS member
            WHERE member.team_id = url.team_id AND member.identity_id = sqlc.arg(identity_id)
              AND member.removed_at IS NULL
              AND ((url.public_url_scope = 'member' AND member.id = url.membership_id)
                OR (url.public_url_scope = 'shared' AND member.role IN ('admin', 'owner')))
        ) AS owner,
        EXISTS (
            SELECT 1 FROM control.visitor_access_grants AS access_grant
            WHERE access_grant.public_url_id = url.id AND access_grant.kind = 'identity_url'
              AND access_grant.identity_id = sqlc.arg(identity_id) AND access_grant.revoked_at IS NULL
              AND (access_grant.expires_at IS NULL OR access_grant.expires_at > sqlc.arg(now)::timestamptz)
        ) AS invited,
        EXISTS (
            SELECT 1 FROM control.visitor_access_grants AS access_grant
            WHERE access_grant.team_id = url.team_id AND access_grant.revoked_at IS NULL
              AND (access_grant.expires_at IS NULL OR access_grant.expires_at > sqlc.arg(now)::timestamptz)
              AND (access_grant.kind = 'team_url' AND access_grant.public_url_id = url.id
                OR access_grant.kind = 'team_preview' AND url.service_protocol = 'http' AND url.purpose = 'app'
                  AND EXISTS (SELECT 1 FROM control.preview_public_urls AS included
                              WHERE included.preview_id = access_grant.preview_id AND included.public_url_id = url.id))
        ) AS shared_with_team,
        EXISTS (
            SELECT 1 FROM control.previews AS preview
            JOIN control.preview_public_urls AS included ON included.preview_id = preview.id
            WHERE included.public_url_id = url.id AND preview.team_id = url.team_id
              AND preview.team_access_enabled AND url.service_protocol = 'http' AND url.purpose = 'app'
        ) AS legacy_team_share
    FROM control.public_urls AS url
    JOIN control.teams AS team ON team.id = url.team_id AND team.deleted_at IS NULL
    JOIN control.identities AS identity ON identity.id = sqlc.arg(identity_id) AND identity.disabled_at IS NULL
    WHERE url.lifecycle_state <> 'deleted'
      AND (sqlc.narg(team_id)::text IS NULL OR url.team_id = sqlc.narg(team_id))
      AND (sqlc.narg(cursor)::text IS NULL OR url.id > sqlc.narg(cursor))
)
SELECT id, team_id, team_name, canonical_hostname, service_protocol, public_port,
       public_url_scope, purpose, lifecycle_state,
       (CASE WHEN owner THEN 'owner'
             WHEN invited THEN 'invite'
             WHEN member AND (shared_with_team OR legacy_team_share) THEN 'team'
             ELSE 'inventory' END)::text AS visitor_access
FROM available
WHERE member OR invited
ORDER BY id LIMIT 101;
