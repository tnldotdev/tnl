-- name: CreateOrGetDNSAuthority :one
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
)
ON CONFLICT (create_idempotency_key) DO UPDATE
SET updated_at = dns_authorities.updated_at
WHERE dns_authorities.create_request_digest = EXCLUDED.create_request_digest
RETURNING *;

-- name: GetDNSAuthority :one
SELECT *
FROM control.dns_authorities
WHERE authority_reference = sqlc.arg(authority_reference);

-- name: GetDNSAuthorityByReleaseIdempotency :one
SELECT *
FROM control.dns_authorities
WHERE release_idempotency_key = sqlc.arg(release_idempotency_key);

-- name: LockDNSAuthority :one
SELECT *
FROM control.dns_authorities
WHERE authority_reference = sqlc.arg(authority_reference)
FOR UPDATE;

-- name: BeginDNSAuthorityRelease :one
UPDATE control.dns_authorities
SET state = 'releasing',
    release_idempotency_key = COALESCE(release_idempotency_key, sqlc.arg(release_idempotency_key)),
    work_revision = work_revision + 1,
    available_at = sqlc.arg(updated_at),
    last_error = NULL,
    updated_at = sqlc.arg(updated_at)
WHERE authority_reference = sqlc.arg(authority_reference)
  AND state IN ('pending', 'ready', 'failed')
RETURNING *;

-- name: ClaimDNSAuthorityWork :one
WITH candidate AS (
    SELECT authority_reference
    FROM control.dns_authorities
    WHERE state IN ('pending', 'releasing')
      AND available_at <= sqlc.arg(claimed_at)
      AND (work_owner IS NULL OR work_expires_at <= sqlc.arg(claimed_at))
    ORDER BY available_at, authority_reference
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
UPDATE control.dns_authorities AS authorities
SET work_owner = sqlc.arg(work_owner),
    work_epoch = authorities.work_epoch + 1,
    work_expires_at = sqlc.arg(work_expires_at),
    attempts = authorities.attempts + 1,
    updated_at = GREATEST(authorities.updated_at, sqlc.arg(claimed_at))
FROM candidate
WHERE authorities.authority_reference = candidate.authority_reference
RETURNING authorities.*;

-- name: SaveDNSAuthorityWork :one
UPDATE control.dns_authorities
SET provider_zone_id = sqlc.narg(provider_zone_id),
    state = sqlc.arg(state),
    nameservers = sqlc.arg(nameservers),
    work_revision = work_revision + 1,
    work_owner = NULL,
    work_expires_at = NULL,
    available_at = sqlc.arg(available_at),
    last_error = sqlc.narg(last_error),
    updated_at = sqlc.arg(completed_at)
WHERE authority_reference = sqlc.arg(authority_reference)
  AND work_owner = sqlc.arg(work_owner)
  AND work_epoch = sqlc.arg(work_epoch)
  AND work_expires_at > sqlc.arg(completed_at)
  AND work_revision = sqlc.arg(expected_work_revision)
RETURNING *;

-- name: LockDNSAuthorityLocalTeam :exec
SELECT teams.id
FROM control.teams AS teams
JOIN control.domains AS domains ON domains.team_id = teams.id
WHERE domains.dns_authority_reference = sqlc.arg(authority_reference)
ORDER BY teams.id
FOR NO KEY UPDATE OF teams;

-- name: LockDNSAuthorityLocalDomain :exec
SELECT id
FROM control.domains
WHERE dns_authority_reference = sqlc.arg(authority_reference)
ORDER BY id
FOR UPDATE;

-- name: DNSAuthorityReleaseReady :one
SELECT
    NOT EXISTS (
        SELECT 1
        FROM control.routes AS routes
        WHERE routes.domain_id = sqlc.arg(authority_domain_id)
          AND routes.lifecycle_state <> 'deleted'
    )
    AND NOT EXISTS (
        SELECT 1
        FROM control.route_sessions AS sessions
        JOIN control.routes AS routes ON routes.id = sessions.route_id
        WHERE routes.domain_id = sqlc.arg(authority_domain_id)
          AND sessions.closed_at IS NULL
    )
    AND NOT EXISTS (
        SELECT 1
        FROM control.acme_orders AS orders
        JOIN control.routes AS routes ON routes.id = orders.route_id
        WHERE routes.domain_id = sqlc.arg(authority_domain_id)
          AND (
              orders.state NOT IN ('waiting_for_install', 'installed', 'failed', 'canceled')
              OR orders.not_after > sqlc.arg(observed_at)
              OR EXISTS (
                  SELECT 1
                  FROM control.acme_authorizations AS authorizations
                  WHERE authorizations.order_id = orders.id
                    AND authorizations.challenge_type = 'dns-01'
                    AND (
                        authorizations.state IN ('presenting', 'presented', 'validating', 'valid', 'cleaning')
                        OR authorizations.presented_at IS NOT NULL AND authorizations.cleanup_completed_at IS NULL
                    )
              )
          )
    )
    AND NOT EXISTS (
        SELECT 1
        FROM control.route_sessions AS sessions
        JOIN control.routes AS routes ON routes.id = sessions.route_id
        WHERE routes.domain_id = sqlc.arg(authority_domain_id)
          AND sessions.certificate_not_after > sqlc.arg(observed_at)
    )
    AND NOT EXISTS (
        SELECT 1
        FROM control.routes AS routes
        WHERE routes.domain_id = sqlc.arg(authority_domain_id)
          AND routes.dns_state NOT IN ('unmanaged', 'removed')
    ) AS ready;

-- name: UpdateLocalDomainForDNSAuthority :one
UPDATE control.domains
SET state = sqlc.arg(state),
    verified_at = CASE
        WHEN sqlc.arg(state)::text = 'ready' THEN COALESCE(verified_at, sqlc.arg(updated_at))
        ELSE verified_at
    END,
    released_at = CASE
        WHEN sqlc.arg(state)::text = 'released' THEN COALESCE(released_at, sqlc.arg(updated_at))
        ELSE released_at
    END,
    reusable_after = CASE
        WHEN sqlc.arg(state)::text = 'released' THEN COALESCE(reusable_after, sqlc.arg(updated_at))
        ELSE reusable_after
    END,
    updated_at = sqlc.arg(updated_at)
WHERE dns_authority_reference = sqlc.arg(authority_reference)
RETURNING id, team_id, make_default_when_ready;

-- name: SetDNSReadyDomainDefault :one
UPDATE control.teams AS teams
SET default_domain_id = domains.id,
    policy_revision = teams.policy_revision + 1,
    updated_at = sqlc.arg(updated_at)
FROM control.domains AS domains
WHERE domains.dns_authority_reference = sqlc.arg(authority_reference)
  AND domains.team_id = teams.id
  AND domains.state = 'ready'
  AND domains.make_default_when_ready
  AND teams.default_domain_id IS DISTINCT FROM domains.id
  AND teams.deleted_at IS NULL
RETURNING teams.policy_revision;

-- name: SetDomainAuthorityRevision :exec
UPDATE control.domains
SET authority_revision = sqlc.arg(authority_revision),
    updated_at = sqlc.arg(updated_at)
WHERE dns_authority_reference = sqlc.arg(authority_reference);
