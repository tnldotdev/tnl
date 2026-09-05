-- name: ListIdentityTeams :many
SELECT
    t.id,
    t.kind,
    t.display_name,
    t.managed_label,
    t.default_domain_id,
    t.policy_revision,
    t.created_at,
    t.updated_at
FROM control.teams AS t
JOIN control.team_memberships AS m
  ON m.team_id = t.id
 AND m.identity_id = sqlc.arg(identity_id)
 AND m.removed_at IS NULL
WHERE t.deleted_at IS NULL
ORDER BY t.created_at, t.id;

-- name: GetIdentityTeam :one
SELECT
    t.id,
    t.kind,
    t.display_name,
    t.managed_label,
    t.default_domain_id,
    t.policy_revision,
    t.created_at,
    t.updated_at
FROM control.teams AS t
JOIN control.team_memberships AS m
  ON m.team_id = t.id
 AND m.identity_id = sqlc.arg(identity_id)
 AND m.removed_at IS NULL
WHERE t.id = sqlc.arg(team_id)
  AND t.deleted_at IS NULL;

-- name: ListIdentityTeamDomains :many
SELECT
    d.id,
    d.kind,
    d.team_id,
    d.canonical_domain,
    d.state,
    d.authority_revision,
    d.created_at,
    d.verified_at,
    d.updated_at
FROM control.domains AS d
WHERE d.released_at IS NULL
  AND (
      d.kind = 'managed'
      OR d.team_id = sqlc.arg(team_id)
  )
  AND EXISTS (
      SELECT 1
      FROM control.team_memberships AS m
      WHERE m.team_id = sqlc.arg(team_id)
        AND m.identity_id = sqlc.arg(identity_id)
        AND m.removed_at IS NULL
  )
ORDER BY CASE d.kind WHEN 'managed' THEN 0 ELSE 1 END, d.canonical_domain, d.id;
