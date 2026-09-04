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

-- name: InsertCertificateIssuance :execrows
INSERT INTO certificate_issuances (
    id,
    route_id,
    route_version,
    hostname,
    directory_url,
    acme_profile,
    status,
    csr_der,
    csr_hash,
    spki_hash,
    created_at,
    updated_at
)
SELECT
    sqlc.arg(id),
    route.id,
    route.route_version,
    route.hostname,
    sqlc.arg(directory_url),
    sqlc.arg(acme_profile),
    'creating_order',
    sqlc.arg(csr_der),
    sqlc.arg(csr_hash),
    sqlc.arg(spki_hash),
    sqlc.arg(created_at),
    sqlc.arg(updated_at)
FROM routes AS route
WHERE route.id = sqlc.arg(route_id)
    AND route.route_version = sqlc.arg(route_version)
    AND route.hostname = sqlc.arg(hostname)
    AND route.status = 'enabled'
    AND (route.authorization_expires_at IS NULL OR route.authorization_expires_at > sqlc.arg(now))
ON CONFLICT (route_id, route_version, csr_hash, directory_url, acme_profile) DO NOTHING;

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
WHERE route_id = sqlc.arg(route_id)
    AND route_version = sqlc.arg(route_version)
    AND csr_hash = sqlc.arg(csr_hash)
    AND directory_url = sqlc.arg(directory_url)
    AND acme_profile = sqlc.arg(acme_profile);

-- name: FindRebindableCertificateIssuance :one
SELECT * FROM certificate_issuances
WHERE route_id = sqlc.arg(route_id)
    AND csr_hash = sqlc.arg(csr_hash)
    AND directory_url = sqlc.arg(directory_url)
    AND acme_profile = sqlc.arg(acme_profile)
    AND status != 'failed'
    AND (
        certificate_pem IS NULL
        OR status IN ('waiting_for_install', 'installed')
            AND renew_at > CAST(sqlc.arg(now) AS INTEGER)
            AND not_after > CAST(sqlc.arg(valid_after) AS INTEGER)
    )
ORDER BY created_at DESC
LIMIT 1;

-- name: RebindCertificateIssuance :execrows
UPDATE certificate_issuances
SET
    route_version = sqlc.arg(route_version),
    status = CASE WHEN certificate_pem IS NOT NULL THEN 'waiting_for_install' ELSE status END,
    updated_at = sqlc.arg(updated_at)
WHERE certificate_issuances.id = sqlc.arg(issuance_id)
    AND route_id = sqlc.arg(route_id)
    AND directory_url = sqlc.arg(directory_url)
    AND acme_profile = sqlc.arg(acme_profile)
    AND status != 'failed'
    AND EXISTS (
        SELECT 1
        FROM routes AS route
        WHERE route.id = certificate_issuances.route_id
            AND route.route_version = sqlc.arg(route_version)
            AND route.hostname = certificate_issuances.hostname
            AND route.status = 'enabled'
            AND (route.authorization_expires_at IS NULL OR route.authorization_expires_at > sqlc.arg(now))
    );

-- name: HasBlockingCertificateIssuance :one
SELECT CAST(EXISTS (
    SELECT 1
    FROM certificate_issuances
    WHERE route_id = sqlc.arg(route_id)
        AND route_version = sqlc.arg(route_version)
        AND csr_hash != sqlc.arg(csr_hash)
        AND directory_url = sqlc.arg(directory_url)
        AND acme_profile = sqlc.arg(acme_profile)
        AND (
            status NOT IN ('installed', 'failed')
            OR status = 'installed' AND renew_at > CAST(sqlc.arg(now) AS INTEGER)
        )
) AS INTEGER);

-- name: GetRecentCertificateAttempts :one
SELECT COUNT(*), CAST(COALESCE(MIN(order_started_at), 0) AS INTEGER) AS earliest_started_at
FROM certificate_issuances
WHERE route_id = sqlc.arg(route_id)
    AND order_started_at >= sqlc.arg(started_after);

-- name: UpdateCertificateIssuance :execrows
UPDATE certificate_issuances
SET
    status = sqlc.arg(status),
    order_started_at = sqlc.arg(order_started_at),
    order_url = sqlc.arg(order_url),
    order_expires_at = sqlc.arg(order_expires_at),
    retry_at = sqlc.arg(retry_at),
    authorization_url = sqlc.arg(authorization_url),
    finalize_url = sqlc.arg(finalize_url),
    challenge_url = sqlc.arg(challenge_url),
    challenge_digest = sqlc.arg(challenge_digest),
    challenge_expires_at = sqlc.arg(challenge_expires_at),
    certificate_url = sqlc.arg(certificate_url),
    certificate_pem = sqlc.arg(certificate_pem),
    not_before = sqlc.arg(not_before),
    not_after = sqlc.arg(not_after),
    renew_at = sqlc.arg(renew_at),
    last_error = sqlc.arg(last_error),
    updated_at = sqlc.arg(updated_at)
WHERE certificate_issuances.id = sqlc.arg(issuance_id)
    AND directory_url = sqlc.arg(directory_url)
    AND acme_profile = sqlc.arg(acme_profile)
    AND EXISTS (
        SELECT 1
        FROM routes AS route
        WHERE route.id = certificate_issuances.route_id
            AND route.route_version = certificate_issuances.route_version
            AND route.hostname = certificate_issuances.hostname
            AND route.status = 'enabled'
            AND (route.authorization_expires_at IS NULL OR route.authorization_expires_at > sqlc.arg(now))
    );

-- name: RemoveCertificateChallenge :execrows
UPDATE certificate_issuances
SET
    challenge_url = NULL,
    challenge_digest = NULL,
    challenge_expires_at = NULL,
    last_error = CASE WHEN challenge_url IS NULL THEN last_error ELSE NULL END,
    updated_at = CASE WHEN challenge_url IS NULL THEN updated_at ELSE sqlc.arg(updated_at) END
WHERE certificate_issuances.id = sqlc.arg(issuance_id)
    AND (certificate_pem IS NOT NULL OR status = 'failed')
    AND EXISTS (
        SELECT 1
        FROM routes AS route
        WHERE route.id = certificate_issuances.route_id
            AND route.route_version = certificate_issuances.route_version
            AND route.hostname = certificate_issuances.hostname
            AND route.status = 'enabled'
            AND (route.authorization_expires_at IS NULL OR route.authorization_expires_at > sqlc.arg(now))
    );

-- name: MarkCertificateInstalled :execrows
UPDATE certificate_issuances
SET
    status = 'installed',
    last_error = NULL,
    updated_at = CASE WHEN status = 'installed' THEN updated_at ELSE sqlc.arg(updated_at) END
WHERE certificate_issuances.id = sqlc.arg(issuance_id)
    AND certificate_issuances.route_id = sqlc.arg(expected_route_id)
    AND certificate_issuances.route_version = sqlc.arg(expected_route_version)
    AND certificate_issuances.status IN ('waiting_for_install', 'installed')
    AND certificate_issuances.certificate_pem IS NOT NULL
    AND certificate_issuances.challenge_url IS NULL
    AND EXISTS (
        SELECT 1
        FROM routes AS route
        WHERE route.id = certificate_issuances.route_id
            AND route.route_version = certificate_issuances.route_version
            AND route.hostname = certificate_issuances.hostname
            AND route.status = 'enabled'
            AND (route.authorization_expires_at IS NULL OR route.authorization_expires_at > sqlc.arg(now))
    );
