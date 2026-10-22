-- name: ConsumeAuthenticationSeed :execrows
INSERT INTO control.authentication_seeds (seed_key, applied_at) VALUES (sqlc.arg(seed_key), sqlc.arg(applied_at))
ON CONFLICT (seed_key) DO NOTHING;

-- name: SeedAdministrator :exec
WITH seed AS (
    INSERT INTO control.authentication_seeds (seed_key, applied_at) VALUES (sqlc.arg(seed_key), sqlc.arg(applied_at))
    ON CONFLICT (seed_key) DO NOTHING RETURNING seed_key
)
UPDATE control.identities SET administrator = true WHERE id = sqlc.arg(identity_id) AND EXISTS (SELECT 1 FROM seed);

-- name: FindSeedTeam :one
SELECT * FROM control.teams WHERE display_name = sqlc.arg(display_name) AND kind = 'organization' AND deleted_at IS NULL;

-- name: HasTeamMembershipHistory :one
SELECT EXISTS (SELECT 1 FROM control.team_memberships WHERE team_id = sqlc.arg(team_id) AND identity_id = sqlc.arg(identity_id));

-- name: CreateSeedMember :exec
INSERT INTO control.team_memberships (id, team_id, identity_id, slug_reservation_id, managed_label, role, authority_revision, created_at, updated_at)
VALUES (sqlc.arg(id), sqlc.arg(team_id), sqlc.arg(identity_id), sqlc.arg(slug_reservation_id), sqlc.arg(managed_label), 'member', 1, sqlc.arg(created_at), sqlc.arg(created_at));

-- name: SetIdentityInitialTeam :exec
UPDATE control.identities SET initial_team_id = sqlc.arg(team_id) WHERE id = sqlc.arg(identity_id) AND initial_team_id IS NULL;

-- name: BindInitialOIDCMembership :exec
UPDATE control.team_memberships SET identity_connection_id=sqlc.narg(connection_id)
WHERE team_id=sqlc.arg(team_id) AND identity_id=sqlc.arg(identity_id) AND identity_connection_id IS NULL AND removed_at IS NULL AND manual_suspended_at IS NULL;
