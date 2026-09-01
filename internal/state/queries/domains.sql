-- name: InsertDomainChallenge :exec
INSERT INTO domain_claim_challenges (
    id, principal_id, request_key, domain, token, verification_target,
    is_apex, state, created_at
) VALUES (
    sqlc.arg(id), sqlc.arg(principal_id), sqlc.arg(request_key),
    sqlc.arg(domain), sqlc.arg(token), sqlc.arg(verification_target),
    sqlc.arg(is_apex), 'pending_dns', sqlc.arg(created_at)
);

-- name: GetDomainChallenge :one
SELECT domain_claim_challenges.*
FROM domain_claim_challenges
WHERE id = sqlc.arg(id);

-- name: GetDomainChallengeRequest :one
SELECT domain_claim_challenges.*
FROM domain_claim_challenges
WHERE principal_id = sqlc.arg(principal_id)
    AND request_key = sqlc.arg(request_key);

-- name: CountDomainChallenges :one
SELECT COUNT(*)
FROM domain_claim_challenges
WHERE principal_id = sqlc.arg(principal_id)
    AND state = 'pending_dns';

-- name: ListActiveCustomDomainClaims :many
SELECT hostname_claims.*
FROM hostname_claims
WHERE kind = 'persistent_custom_domain'
    AND state = 'active'
ORDER BY hostname;

-- name: InsertCustomDomainClaim :exec
INSERT INTO hostname_claims (
    id, principal_id, hostname, created_at, irreversible,
    kind, state, source, activated_at
) VALUES (
    sqlc.arg(id), sqlc.arg(principal_id), sqlc.arg(hostname),
    sqlc.arg(created_at), 0, 'persistent_custom_domain', 'active',
    'custom', sqlc.arg(created_at)
);

-- name: ActivateReleasedCustomDomainClaim :execrows
UPDATE hostname_claims
SET principal_id = sqlc.arg(principal_id), state = 'active',
    activated_at = sqlc.arg(activated_at), released_at = NULL, reason = NULL
WHERE id = sqlc.arg(id)
    AND kind = 'persistent_custom_domain'
    AND state = 'released';

-- name: VerifyDomainChallenge :execrows
UPDATE domain_claim_challenges
SET state = 'verified', claim_id = sqlc.arg(claim_id),
    verified_at = sqlc.arg(verified_at)
WHERE id = sqlc.arg(id)
    AND principal_id = sqlc.arg(principal_id)
    AND state = 'pending_dns';

-- name: InvalidateOtherDomainChallenges :exec
UPDATE domain_claim_challenges
SET state = 'invalidated', invalidated_at = sqlc.arg(invalidated_at)
WHERE domain = sqlc.arg(domain)
    AND id != sqlc.arg(id)
    AND state = 'pending_dns';

-- name: InvalidateDomainChallengesForClaim :exec
UPDATE domain_claim_challenges
SET state = 'invalidated', invalidated_at = sqlc.arg(invalidated_at)
WHERE domain = sqlc.arg(domain)
    AND state = 'pending_dns';
