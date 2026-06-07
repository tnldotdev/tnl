-- name: GetACMEAccount :one
SELECT directory_url, email, key_der, kid, accepted_terms_url, created_at, updated_at
FROM acme_accounts
WHERE directory_url = ?;

-- name: InsertACMEAccount :exec
INSERT INTO acme_accounts (
    directory_url,
    email,
    key_der,
    kid,
    accepted_terms_url,
    created_at,
    updated_at
)
VALUES (?, ?, ?, NULL, NULL, ?, ?);

-- name: UpdateACMEAccount :execrows
UPDATE acme_accounts
SET email = ?, kid = ?, accepted_terms_url = ?, updated_at = ?
WHERE directory_url = ?;

-- name: InsertCertificateIssuance :exec
INSERT INTO certificate_issuances (
    id,
    route_id,
    route_version,
    hostname,
    acme_profile,
    status,
    csr_der,
    csr_hash,
    spki_hash,
    created_at,
    updated_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (route_id, route_version, csr_hash) DO NOTHING;

-- name: GetEnabledRouteHostname :one
SELECT hostname
FROM routes
WHERE id = sqlc.arg(route_id)
    AND route_version = sqlc.arg(route_version)
    AND status = 'enabled'
    AND (authorization_expires_at IS NULL OR authorization_expires_at > sqlc.arg(now));

-- name: GetCertificateIssuance :one
SELECT * FROM certificate_issuances
WHERE id = ?;

-- name: FindBoundCertificateIssuance :one
SELECT * FROM certificate_issuances
WHERE route_id = ? AND route_version = ? AND csr_hash = ?;

-- name: FindResumableCertificateIssuance :one
SELECT * FROM certificate_issuances
WHERE route_id = ? AND csr_hash = ? AND certificate_pem IS NULL
    AND status NOT IN ('installed', 'failed', 'blocked', 'canceled')
    AND (order_expires_at IS NULL OR order_expires_at > CAST(sqlc.arg(now) AS INTEGER))
    AND (challenge_expires_at IS NULL OR challenge_expires_at > CAST(sqlc.arg(now) AS INTEGER))
ORDER BY created_at DESC
LIMIT 1;

-- name: RebindCertificateIssuance :execrows
UPDATE certificate_issuances
SET route_version = ?, updated_at = ?
WHERE id = ?;

-- name: HasBlockingCertificateIssuance :one
SELECT CAST(EXISTS (
    SELECT 1
    FROM certificate_issuances
    WHERE route_id = ? AND route_version = ? AND csr_hash != ?
        AND (
            status NOT IN ('installed', 'failed', 'blocked', 'canceled')
            OR (status = 'installed' AND renew_at > CAST(sqlc.arg(now) AS INTEGER))
        )
) AS INTEGER);

-- name: GetRecentCertificateAttempts :one
SELECT COUNT(*), CAST(COALESCE(MIN(created_at), 0) AS INTEGER) AS earliest_created_at
FROM certificate_issuances
WHERE route_id = ? AND order_attempts > 0 AND created_at >= ?;

-- name: FindReusableCertificateIssuance :one
SELECT * FROM certificate_issuances
WHERE route_id = sqlc.arg(route_id)
    AND csr_hash = sqlc.arg(csr_hash)
    AND certificate_pem IS NOT NULL
    AND not_after > CAST(sqlc.arg(valid_after) AS INTEGER)
    AND status IN ('waiting_for_install', 'installed')
ORDER BY not_after DESC
LIMIT 1;

-- name: UpdateCertificateIssuance :execrows
UPDATE certificate_issuances
SET
    status = sqlc.arg(status),
    order_url = sqlc.arg(order_url),
    acme_status = sqlc.arg(acme_status),
    order_attempts = sqlc.arg(order_attempts),
    order_expires_at = sqlc.arg(order_expires_at),
    retry_at = sqlc.arg(retry_at),
    authorization_url = sqlc.arg(authorization_url),
    finalize_url = sqlc.arg(finalize_url),
    challenge_url = sqlc.arg(challenge_url),
    challenge_token = sqlc.arg(challenge_token),
    challenge_digest = sqlc.arg(challenge_digest),
    challenge_expires_at = sqlc.arg(challenge_expires_at),
    certificate_url = sqlc.arg(certificate_url),
    certificate_pem = sqlc.arg(certificate_pem),
    not_before = sqlc.arg(not_before),
    not_after = sqlc.arg(not_after),
    renew_at = sqlc.arg(renew_at),
    installed_at = sqlc.arg(installed_at),
    challenge_removed_at = sqlc.arg(challenge_removed_at),
    last_error = sqlc.arg(last_error),
    updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id);
