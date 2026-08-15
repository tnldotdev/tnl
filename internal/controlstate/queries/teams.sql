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
	 d.dns_authority_reference,
	 d.state,
    d.authority_revision,
    COALESCE(a.nameservers, '{}'::text[]) AS nameservers,
    d.created_at,
    d.verified_at,
    d.updated_at
FROM control.domains AS d
LEFT JOIN control.dns_authorities AS a
  ON a.authority_reference = d.dns_authority_reference
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

-- name: LockIdentityForTeamCreation :one
SELECT id
FROM control.identities
WHERE id = sqlc.arg(identity_id)
  AND disabled_at IS NULL
FOR NO KEY UPDATE;

-- name: GetOrganizationTeamByIdempotency :one
SELECT
    id,
    kind,
    display_name,
    managed_label,
    default_domain_id,
    policy_revision,
    creation_request_digest,
    created_at,
    updated_at
FROM control.teams
WHERE created_by_identity_id = sqlc.arg(identity_id)
  AND creation_idempotency_key = sqlc.arg(idempotency_key)
  AND kind = 'organization';

-- name: CreateOrganizationTeam :one
INSERT INTO control.teams (
    id,
    kind,
    display_name,
    managed_label,
    default_domain_id,
    created_by_identity_id,
    creation_idempotency_key,
    creation_request_digest,
    created_at,
    updated_at
) VALUES (
    sqlc.arg(id),
    'organization',
    sqlc.arg(display_name),
    sqlc.arg(managed_label),
    sqlc.arg(default_domain_id),
    sqlc.arg(created_by_identity_id),
    sqlc.arg(creation_idempotency_key),
    sqlc.arg(creation_request_digest),
    sqlc.arg(created_at),
    sqlc.arg(created_at)
)
RETURNING id, kind, display_name, managed_label, default_domain_id, policy_revision, created_at, updated_at;

-- name: GetTeamActorContext :one
SELECT
    t.id,
    t.kind,
    t.display_name,
    t.managed_label,
    t.default_domain_id,
    t.policy_revision,
    t.created_at,
    t.updated_at,
    actor.id AS actor_membership_id,
    actor.role AS actor_role
FROM control.teams AS t
JOIN control.team_memberships AS actor
  ON actor.team_id = t.id
 AND actor.identity_id = sqlc.arg(identity_id)
 AND actor.removed_at IS NULL
WHERE t.id = sqlc.arg(team_id)
  AND t.deleted_at IS NULL;

-- name: LockTeamActorContext :one
SELECT
    t.id,
    t.kind,
    t.display_name,
    t.managed_label,
    t.default_domain_id,
    t.policy_revision,
    t.created_at,
    t.updated_at,
    actor.id AS actor_membership_id,
    actor.role AS actor_role
FROM control.teams AS t
JOIN control.team_memberships AS actor
  ON actor.team_id = t.id
 AND actor.identity_id = sqlc.arg(identity_id)
 AND actor.removed_at IS NULL
WHERE t.id = sqlc.arg(team_id)
  AND t.deleted_at IS NULL
FOR UPDATE OF t, actor;

-- Local authority mutations lock the team before identities, memberships,
-- domains, DNS authorities, and routes. Authorization is rechecked under this
-- transaction-held guard; hosted teams never require fabricated local rows.
-- name: LockLocalTeamForMutation :one
SELECT id
FROM control.teams
WHERE id = sqlc.arg(team_id)
  AND deleted_at IS NULL
FOR NO KEY UPDATE;

-- name: ListTeamMembershipContexts :many
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
JOIN control.teams AS t ON t.id = m.team_id
JOIN control.member_slug_reservations AS s ON s.id = m.slug_reservation_id
WHERE m.team_id = sqlc.arg(team_id)
  AND m.removed_at IS NULL
ORDER BY m.created_at, m.id;

-- name: GetTeamMembershipContext :one
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
JOIN control.teams AS t ON t.id = m.team_id
JOIN control.member_slug_reservations AS s ON s.id = m.slug_reservation_id
WHERE m.id = sqlc.arg(membership_id)
  AND m.team_id = sqlc.arg(team_id)
  AND m.removed_at IS NULL;

-- name: LockTeamMembership :one
SELECT m.*, s.member_slug
FROM control.team_memberships AS m
JOIN control.member_slug_reservations AS s ON s.id = m.slug_reservation_id
WHERE m.id = sqlc.arg(membership_id)
  AND m.team_id = sqlc.arg(team_id)
  AND m.removed_at IS NULL
FOR UPDATE OF m, s;

-- name: CountTeamOwners :one
SELECT count(*)
FROM control.team_memberships
WHERE team_id = sqlc.arg(team_id)
  AND role = 'owner'
  AND removed_at IS NULL;

-- name: AdvanceTeamPolicyRevision :one
UPDATE control.teams
SET policy_revision = policy_revision + 1,
    updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(team_id)
  AND deleted_at IS NULL
RETURNING policy_revision;

-- name: UpdateMembershipRole :execrows
UPDATE control.team_memberships
SET role = sqlc.arg(role),
    authority_revision = sqlc.arg(authority_revision),
    updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(membership_id)
  AND team_id = sqlc.arg(team_id)
  AND removed_at IS NULL;

-- name: RemoveTeamMembership :execrows
UPDATE control.team_memberships
SET authority_revision = sqlc.arg(authority_revision),
    updated_at = sqlc.arg(removed_at),
    removed_at = sqlc.arg(removed_at),
    removed_by_identity_id = sqlc.arg(removed_by_identity_id)
WHERE id = sqlc.arg(membership_id)
  AND team_id = sqlc.arg(team_id)
  AND removed_at IS NULL;

-- name: QuarantineMemberSlug :execrows
UPDATE control.member_slug_reservations
SET state = 'quarantined',
    quarantined_at = sqlc.arg(quarantined_at),
    reusable_after = NULL,
    released_at = NULL
WHERE id = sqlc.arg(slug_reservation_id)
  AND state = 'active';

-- name: LockMembershipRoutes :many
SELECT routes.*
FROM control.routes AS routes
WHERE routes.team_id = sqlc.arg(team_id)
  AND (
      routes.membership_id = sqlc.arg(membership_id)
      OR EXISTS (
          SELECT 1
          FROM control.route_sessions AS sessions
          WHERE sessions.route_id = routes.id
            AND sessions.membership_id = sqlc.arg(membership_id)
            AND sessions.closed_at IS NULL
      )
  )
  AND routes.lifecycle_state <> 'deleted'
ORDER BY routes.id
FOR UPDATE;

-- name: LockDomainRoutes :many
SELECT *
FROM control.routes
WHERE team_id = sqlc.arg(team_id)
  AND domain_id = sqlc.arg(domain_id)
  AND lifecycle_state <> 'deleted'
ORDER BY id
FOR UPDATE;

-- name: SuspendAuthorityRoute :execrows
UPDATE control.routes
SET lifecycle_state = 'suspended',
    dns_state = CASE
        WHEN dns_state NOT IN ('unmanaged', 'removed') THEN 'removing'
        ELSE dns_state
    END,
    dns_revision = CASE
        WHEN dns_state NOT IN ('unmanaged', 'removed') THEN dns_revision + 1
        ELSE dns_revision
    END,
    dns_work_owner = NULL,
    dns_work_expires_at = NULL,
    dns_available_at = CASE
        WHEN dns_state NOT IN ('unmanaged', 'removed') THEN sqlc.arg(suspended_at)
        ELSE dns_available_at
    END,
    dns_last_error = NULL,
    mutation_revision = mutation_revision + 1,
    suspension_revision = suspension_revision + 1,
    suspension_reason = sqlc.arg(suspension_reason),
    suspended_at = sqlc.arg(suspended_at),
    updated_at = sqlc.arg(suspended_at)
WHERE id = sqlc.arg(route_id)
  AND lifecycle_state <> 'deleted'
  AND mutation_revision < 9223372036854775807;

-- name: ExpireTeamInvitations :many
UPDATE control.team_invitations
SET state = 'expired'
WHERE team_id = sqlc.arg(team_id)
  AND state = 'pending'
  AND expires_at <= sqlc.arg(now)
RETURNING slug_reservation_id;

-- name: ListTeamInvitations :many
SELECT i.*, s.member_slug
FROM control.team_invitations AS i
JOIN control.member_slug_reservations AS s ON s.id = i.slug_reservation_id
WHERE i.team_id = sqlc.arg(team_id)
ORDER BY i.created_at, i.id;

-- name: GetInvitationByIdempotency :one
SELECT i.*, s.member_slug
FROM control.team_invitations AS i
JOIN control.member_slug_reservations AS s ON s.id = i.slug_reservation_id
WHERE i.invited_by_identity_id = sqlc.arg(identity_id)
  AND i.team_id = sqlc.arg(team_id)
  AND i.idempotency_key = sqlc.arg(idempotency_key)
FOR UPDATE OF i, s;

-- name: ReserveInvitedMemberSlug :one
INSERT INTO control.member_slug_reservations (
    id,
    team_id,
    member_slug,
    state,
    reserved_by_identity_id,
    created_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(team_id),
    sqlc.arg(member_slug),
    'invited',
    sqlc.arg(reserved_by_identity_id),
    sqlc.arg(created_at)
)
ON CONFLICT (team_id, member_slug) DO UPDATE SET
    state = 'invited',
    reserved_by_identity_id = EXCLUDED.reserved_by_identity_id,
    created_at = EXCLUDED.created_at,
    activated_at = NULL,
    quarantined_at = NULL,
    reusable_after = NULL,
    released_at = NULL
WHERE control.member_slug_reservations.state = 'released'
RETURNING id;

-- name: CreateTeamInvitation :one
INSERT INTO control.team_invitations (
    id,
    team_id,
    slug_reservation_id,
    initial_role,
    invited_by_identity_id,
    idempotency_key,
    request_digest,
    token_digest,
    normalized_email_restriction,
    state,
    created_at,
    expires_at
) VALUES (
    sqlc.arg(id),
    sqlc.arg(team_id),
    sqlc.arg(slug_reservation_id),
    sqlc.arg(initial_role),
    sqlc.arg(invited_by_identity_id),
    sqlc.arg(idempotency_key),
    sqlc.arg(request_digest),
    sqlc.arg(token_digest),
    sqlc.narg(normalized_email_restriction),
    'pending',
    sqlc.arg(created_at),
    sqlc.arg(expires_at)
)
RETURNING *;

-- name: LockTeamInvitation :one
SELECT i.*, s.member_slug
FROM control.team_invitations AS i
JOIN control.member_slug_reservations AS s ON s.id = i.slug_reservation_id
WHERE i.id = sqlc.arg(invitation_id)
  AND i.team_id = sqlc.arg(team_id)
FOR UPDATE OF i, s;

-- name: LockInvitationByTokenDigest :one
SELECT
    i.*,
    s.member_slug,
    t.kind AS team_kind,
    t.display_name AS team_display_name,
    accepting.normalized_email AS accepting_normalized_email,
    accepting.email_verified AS accepting_email_verified
FROM control.team_invitations AS i
JOIN control.member_slug_reservations AS s ON s.id = i.slug_reservation_id
JOIN control.teams AS t ON t.id = i.team_id AND t.deleted_at IS NULL
JOIN control.identities AS accepting
  ON accepting.id = sqlc.arg(identity_id)
 AND accepting.disabled_at IS NULL
WHERE i.token_digest = sqlc.arg(token_digest)
FOR UPDATE OF i, s, t, accepting;

-- name: FindInvitationTeamByTokenDigest :one
SELECT team_id
FROM control.team_invitations
WHERE token_digest = sqlc.arg(token_digest);

-- name: LockTeamForInvitationAcceptance :one
SELECT id
FROM control.teams
WHERE id = sqlc.arg(team_id)
  AND kind = 'organization'
  AND deleted_at IS NULL
FOR UPDATE;

-- name: TeamMembershipIdentityExists :one
SELECT EXISTS (
    SELECT 1
    FROM control.team_memberships
    WHERE team_id = sqlc.arg(team_id)
      AND identity_id = sqlc.arg(identity_id)
      AND removed_at IS NULL
);

-- name: ActivateMemberSlug :execrows
UPDATE control.member_slug_reservations
SET state = 'active',
    reserved_by_identity_id = sqlc.arg(identity_id),
    activated_at = sqlc.arg(activated_at),
    released_at = NULL
WHERE id = sqlc.arg(slug_reservation_id)
  AND state = 'invited';

-- name: CreateTeamMembership :exec
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
    sqlc.arg(role),
    sqlc.arg(authority_revision),
    sqlc.arg(created_at),
    sqlc.arg(created_at)
);

-- name: AcceptTeamInvitation :execrows
UPDATE control.team_invitations
SET state = 'accepted',
    accepted_at = sqlc.arg(accepted_at),
    accepted_by_identity_id = sqlc.arg(identity_id),
    accepted_membership_id = sqlc.arg(membership_id)
WHERE id = sqlc.arg(invitation_id)
  AND state = 'pending';

-- name: RevokeTeamInvitation :execrows
UPDATE control.team_invitations
SET state = 'revoked',
    revoked_at = sqlc.arg(revoked_at),
    revoked_by_identity_id = sqlc.arg(identity_id)
WHERE id = sqlc.arg(invitation_id)
  AND state = 'pending';

-- name: MarkInvitationExpired :execrows
UPDATE control.team_invitations
SET state = 'expired'
WHERE id = sqlc.arg(invitation_id)
  AND state = 'pending';

-- name: ReleaseInvitedMemberSlug :execrows
UPDATE control.member_slug_reservations
SET state = 'released',
    released_at = sqlc.arg(released_at)
WHERE id = sqlc.arg(slug_reservation_id)
  AND state = 'invited';

-- name: LockManagedDomainForClaim :one
SELECT *
FROM control.domains
WHERE kind = 'managed'
  AND released_at IS NULL
FOR UPDATE;

-- name: ListCurrentDomainNames :many
SELECT canonical_domain
FROM control.domains
WHERE released_at IS NULL
ORDER BY canonical_domain;

-- name: GetClaimedDomainByIdempotency :one
SELECT d.*, COALESCE(a.nameservers, '{}'::text[]) AS nameservers
FROM control.domains AS d
LEFT JOIN control.dns_authorities AS a ON a.authority_reference = d.dns_authority_reference
WHERE d.created_by_identity_id = sqlc.arg(identity_id)
  AND d.team_id = sqlc.arg(team_id)
  AND d.claim_idempotency_key = sqlc.arg(idempotency_key)
  AND d.kind = 'claimed';

-- name: CreateClaimedDNSAuthority :exec
INSERT INTO control.dns_authorities (
    authority_reference,
    team_id,
    domain_id,
    canonical_domain,
    create_idempotency_key,
    create_request_digest,
    provider,
    state,
    available_at,
    created_at,
    updated_at
) VALUES (
    sqlc.arg(authority_reference),
    sqlc.arg(team_id),
    sqlc.arg(domain_id),
    sqlc.arg(canonical_domain),
    sqlc.arg(create_idempotency_key),
    sqlc.arg(create_request_digest),
    'route53',
    'pending',
    sqlc.arg(created_at),
    sqlc.arg(created_at),
    sqlc.arg(created_at)
);

-- name: CreateClaimedDomain :one
INSERT INTO control.domains (
    id,
    kind,
    team_id,
    canonical_domain,
    dns_authority_reference,
    state,
    authority_revision,
    created_by_identity_id,
    claim_idempotency_key,
    claim_request_digest,
    make_default_when_ready,
    created_at,
    updated_at
) VALUES (
    sqlc.arg(id),
    'claimed',
    sqlc.arg(team_id),
    sqlc.arg(canonical_domain),
    sqlc.arg(dns_authority_reference),
    'pending',
    sqlc.arg(authority_revision),
    sqlc.arg(created_by_identity_id),
    sqlc.arg(claim_idempotency_key),
    sqlc.arg(claim_request_digest),
    sqlc.arg(make_default_when_ready),
    sqlc.arg(created_at),
    sqlc.arg(created_at)
)
RETURNING *;

-- name: LockTeamDomain :one
SELECT d.*, COALESCE(a.nameservers, '{}'::text[]) AS nameservers
FROM control.domains AS d
LEFT JOIN control.dns_authorities AS a ON a.authority_reference = d.dns_authority_reference
WHERE d.id = sqlc.arg(domain_id)
  AND (d.kind = 'managed' OR d.team_id = sqlc.arg(team_id))
  AND d.released_at IS NULL
FOR UPDATE OF d;

-- name: SetTeamDefaultDomain :execrows
UPDATE control.teams
SET default_domain_id = sqlc.arg(domain_id),
    policy_revision = policy_revision + 1,
    updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(team_id)
  AND deleted_at IS NULL;

-- name: MarkClaimedDomainReleasing :execrows
UPDATE control.domains
SET state = 'releasing',
    authority_revision = sqlc.arg(authority_revision),
    updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(domain_id)
  AND team_id = sqlc.arg(team_id)
  AND kind = 'claimed'
  AND state IN ('pending', 'ready', 'failed');

-- name: MarkDNSAuthorityReleasing :execrows
UPDATE control.dns_authorities
SET state = 'releasing',
    work_revision = work_revision + 1,
    available_at = sqlc.arg(updated_at),
    updated_at = sqlc.arg(updated_at)
WHERE authority_reference = sqlc.arg(authority_reference)
  AND state IN ('pending', 'ready', 'failed');
