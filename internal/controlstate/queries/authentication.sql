-- name: LockIdentityBootstrap :exec
SELECT pg_advisory_xact_lock(837174137711267953);

-- name: FindBuiltinIdentity :one
SELECT *
FROM control.identities
WHERE kind = 'builtin'
  AND disabled_at IS NULL;

-- name: FindManagedDomain :one
SELECT *
FROM control.domains
WHERE kind = 'managed'
  AND released_at IS NULL;

-- name: ReserveManagedLabel :one
INSERT INTO control.managed_label_reservations (label, created_at)
VALUES (sqlc.arg(label), sqlc.arg(created_at))
ON CONFLICT (label) DO NOTHING
RETURNING label;

-- name: CreateIdentity :exec
INSERT INTO control.identities (
    id,
    kind,
    display_name,
    normalized_email,
    email_verified,
    administrator,
    created_at,
    updated_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(kind),
    sqlc.arg(display_name),
    sqlc.narg(normalized_email),
    sqlc.arg(email_verified),
    sqlc.arg(administrator),
    sqlc.arg(created_at),
    sqlc.arg(updated_at)
);

-- name: CreateManagedDomain :exec
INSERT INTO control.domains (
    id,
    kind,
    canonical_domain,
    state,
    authority_revision,
    created_at,
    verified_at,
    updated_at
) VALUES (
    sqlc.arg(id),
    'managed',
    sqlc.arg(canonical_domain),
    'ready',
    1,
    sqlc.arg(created_at),
    sqlc.arg(created_at),
    sqlc.arg(created_at)
);

-- name: CreatePersonalTeam :exec
INSERT INTO control.teams (
    id,
    kind,
    display_name,
    managed_label,
    created_by_identity_id,
    created_at,
    updated_at
) VALUES (
    sqlc.arg(id),
    'personal',
    sqlc.arg(display_name),
    sqlc.arg(managed_label),
    sqlc.arg(created_by_identity_id),
    sqlc.arg(created_at),
    sqlc.arg(created_at)
);

-- name: SetPersonalTeamDefaultDomain :exec
UPDATE control.teams
SET default_domain_id = sqlc.arg(domain_id),
    updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(team_id)
  AND kind = 'personal'
  AND deleted_at IS NULL;

-- name: CreateActiveSlugReservation :exec
INSERT INTO control.member_slug_reservations (
    id,
    team_id,
    member_slug,
    state,
    reserved_by_identity_id,
    created_at,
    activated_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(team_id),
    sqlc.arg(member_slug),
    'active',
    sqlc.arg(identity_id),
    sqlc.arg(created_at),
    sqlc.arg(created_at)
);

-- name: CreateOwnerMembership :exec
INSERT INTO control.team_memberships (
    id,
    team_id,
    identity_id,
    slug_reservation_id,
    managed_label,
    role,
    authority_revision,
    created_at,
    updated_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(team_id),
    sqlc.arg(identity_id),
    sqlc.arg(slug_reservation_id),
    sqlc.arg(managed_label),
    'owner',
    1,
    sqlc.arg(created_at),
    sqlc.arg(created_at)
);

-- name: GetIdentityContextIdentity :one
SELECT
    i.id,
    i.display_name,
    i.normalized_email,
    i.email_verified,
    i.administrator,
    i.created_at,
    t.id AS personal_team_id
FROM control.identities AS i
JOIN control.teams AS t
  ON t.created_by_identity_id = i.id
 AND t.kind = 'personal'
 AND t.deleted_at IS NULL
WHERE i.id = sqlc.arg(identity_id)
  AND i.disabled_at IS NULL;

-- name: ListIdentityMembershipContexts :many
SELECT
    m.id,
    m.team_id,
    m.identity_id,
    t.display_name AS team_display_name,
    t.kind AS team_kind,
    m.role,
    s.member_slug,
    m.managed_label,
    t.policy_revision,
    m.created_at,
    m.updated_at
FROM control.team_memberships AS m
JOIN control.teams AS t
  ON t.id = m.team_id
 AND t.deleted_at IS NULL
JOIN control.member_slug_reservations AS s
  ON s.id = m.slug_reservation_id
WHERE m.identity_id = sqlc.arg(identity_id)
  AND m.removed_at IS NULL
ORDER BY t.created_at, t.id;

-- name: CreateControlSession :exec
INSERT INTO control.control_sessions (
    id,
    identity_id,
    authentication_method,
    authentication_source_revision,
    administrator,
    access_token_id,
    access_token_digest,
    access_expires_at,
    refresh_token_id,
    refresh_token_digest,
    retry_secret_ciphertext,
    retry_secret_storage_key_id,
    refresh_expires_at,
    created_at,
    last_refreshed_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(identity_id),
    sqlc.arg(authentication_method),
    sqlc.arg(authentication_source_revision),
    sqlc.arg(administrator),
    sqlc.arg(access_token_id),
    sqlc.arg(access_token_digest),
    sqlc.arg(access_expires_at),
    sqlc.arg(refresh_token_id),
    sqlc.arg(refresh_token_digest),
    sqlc.arg(retry_secret_ciphertext),
    sqlc.arg(retry_secret_storage_key_id),
    sqlc.arg(refresh_expires_at),
    sqlc.arg(created_at),
    sqlc.arg(created_at)
);

-- name: GetControlSessionByAccessID :one
SELECT
    s.id,
    s.identity_id,
    s.authentication_method,
    s.authentication_source_revision,
    s.access_token_digest,
    s.access_expires_at,
    s.retry_secret_ciphertext,
    s.retry_secret_storage_key_id,
    s.refresh_expires_at,
    i.administrator
FROM control.control_sessions AS s
JOIN control.identities AS i ON i.id = s.identity_id
WHERE s.access_token_id = sqlc.arg(access_token_id)
  AND s.revoked_at IS NULL
  AND i.disabled_at IS NULL;

-- name: LockControlSessionByRefreshID :one
SELECT
    s.id,
    s.identity_id,
    s.authentication_method,
    s.authentication_source_revision,
    s.refresh_token_digest,
    s.refresh_expires_at,
    i.administrator
FROM control.control_sessions AS s
JOIN control.identities AS i ON i.id = s.identity_id
WHERE s.refresh_token_id = sqlc.arg(refresh_token_id)
  AND s.revoked_at IS NULL
  AND i.disabled_at IS NULL
FOR UPDATE OF s;

-- name: RotateControlSessionRetrySecret :exec
UPDATE control.control_sessions
SET retry_secret_ciphertext = sqlc.arg(retry_secret_ciphertext),
    retry_secret_storage_key_id = sqlc.arg(retry_secret_storage_key_id)
WHERE id = sqlc.arg(id)
  AND retry_secret_storage_key_id = sqlc.arg(previous_key_id)
  AND retry_secret_ciphertext = sqlc.arg(previous_ciphertext);

-- name: RotateControlSessionCredentials :execrows
UPDATE control.control_sessions
SET access_token_id = sqlc.arg(access_token_id),
    access_token_digest = sqlc.arg(access_token_digest),
    access_expires_at = sqlc.arg(access_expires_at),
    refresh_token_id = sqlc.arg(refresh_token_id),
    refresh_token_digest = sqlc.arg(refresh_token_digest),
    last_refreshed_at = sqlc.arg(refreshed_at)
WHERE id = sqlc.arg(id)
  AND revoked_at IS NULL
  AND refresh_expires_at > sqlc.arg(refreshed_at);

-- name: RevokeControlSession :execrows
UPDATE control.control_sessions
SET revoked_at = sqlc.arg(revoked_at),
    revoked_by = sqlc.arg(revoked_by)
WHERE id = sqlc.arg(id)
  AND revoked_at IS NULL;
