-- name: InsertDomainVerification :exec
INSERT INTO domain_verifications (
    id, identity_id, request_key, domain, token, verification_target,
    is_apex, status, created_at
) VALUES (
    sqlc.arg(id), CAST(sqlc.arg(identity_id) AS TEXT), sqlc.arg(request_key),
    sqlc.arg(domain), sqlc.arg(token), sqlc.arg(verification_target),
    sqlc.arg(is_apex), 'pending', sqlc.arg(created_at)
);

-- name: GetDomainVerification :one
SELECT domain_verifications.*
FROM domain_verifications
WHERE id = sqlc.arg(id);

-- name: GetDomainVerificationRequest :one
SELECT domain_verifications.*
FROM domain_verifications
WHERE identity_id = CAST(sqlc.arg(identity_id) AS TEXT)
    AND request_key = sqlc.arg(request_key);

-- name: CountDomainVerifications :one
SELECT COUNT(*)
FROM domain_verifications
WHERE identity_id = CAST(sqlc.arg(identity_id) AS TEXT)
    AND status = 'pending';

-- name: ListActiveCustomDomainHostnames :many
SELECT hostnames.*
FROM hostnames
WHERE kind = 'custom_domain'
    AND status = 'active'
ORDER BY hostname;

-- name: InsertCustomDomainHostname :exec
INSERT INTO hostnames (
    id, identity_id, hostname, created_at,
    kind, status, source, activated_at
) VALUES (
    sqlc.arg(id), CAST(sqlc.arg(identity_id) AS TEXT), sqlc.arg(hostname),
    sqlc.arg(created_at), 'custom_domain', 'active',
    'user', sqlc.arg(created_at)
);

-- name: ActivateAvailableCustomDomainHostname :execrows
UPDATE hostnames
SET identity_id = CAST(sqlc.arg(identity_id) AS TEXT), status = 'active',
    activated_at = sqlc.arg(activated_at), deactivated_at = NULL
WHERE id = sqlc.arg(id)
    AND kind = 'custom_domain'
    AND status = 'available';

-- name: TransferActiveCustomDomainHostname :execrows
UPDATE hostnames
SET identity_id = CAST(sqlc.arg(identity_id) AS TEXT),
    activated_at = sqlc.arg(activated_at), deactivated_at = NULL
WHERE id = sqlc.arg(id)
    AND kind = 'custom_domain'
    AND status = 'active'
    AND identity_id != CAST(sqlc.arg(identity_id) AS TEXT);

-- name: CompleteDomainVerification :execrows
UPDATE domain_verifications
SET status = 'verified', hostname_id = sqlc.arg(hostname_id),
    verified_at = sqlc.arg(verified_at)
WHERE id = sqlc.arg(id)
    AND identity_id = CAST(sqlc.arg(identity_id) AS TEXT)
    AND status = 'pending';

-- name: InvalidateOtherDomainVerifications :exec
UPDATE domain_verifications
SET status = 'invalidated', invalidated_at = sqlc.arg(invalidated_at)
WHERE domain = sqlc.arg(domain)
    AND id != sqlc.arg(id)
    AND status IN ('pending', 'verified');

-- name: InvalidateDomainVerificationsForHostname :exec
UPDATE domain_verifications
SET status = 'invalidated', invalidated_at = sqlc.arg(invalidated_at)
WHERE domain = sqlc.arg(domain)
    AND status = 'pending';
