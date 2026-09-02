-- Test-only white-box queries shared by persistence tests.

-- name: CountIdentities :one
SELECT COUNT(*) FROM identities;

-- name: CountIdentityByID :one
SELECT COUNT(*) FROM identities WHERE id = sqlc.arg(id);

-- name: CountAccessCredentials :one
SELECT COUNT(*) FROM access_credentials;

-- name: GetOIDCAssertionExpiry :one
SELECT expires_at FROM oidc_assertion_exchanges LIMIT 1;

-- name: CountHostnameRequestsByHostname :one
SELECT COUNT(*) FROM hostname_requests WHERE hostname_id = sqlc.arg(hostname_id);

-- name: ClearACMEAccountKID :exec
UPDATE acme_accounts SET kid = NULL WHERE directory_url = sqlc.arg(directory_url);

-- name: SetACMEAccountEmail :exec
UPDATE acme_accounts SET email = sqlc.arg(email);

-- name: GetLatestRouteSessionStatus :one
SELECT status
FROM route_sessions
WHERE route_id = sqlc.arg(route_id)
ORDER BY version DESC
LIMIT 1;

-- name: GetLatestCertificateIssuanceStatus :one
SELECT status, installed_at, challenge_removed_at
FROM certificate_issuances
WHERE route_id = sqlc.arg(route_id)
ORDER BY version DESC
LIMIT 1;

-- name: CountCertificateIssuancesByRoute :one
SELECT COUNT(*) FROM certificate_issuances WHERE route_id = sqlc.arg(route_id);

-- name: GetAnyACMEAccountKID :one
SELECT CAST(COALESCE(kid, '') AS TEXT) FROM acme_accounts LIMIT 1;

-- name: SetCertificateRenewalDue :execrows
UPDATE certificate_issuances
SET renew_at = CAST(sqlc.arg(renew_at) AS INTEGER)
WHERE id = sqlc.arg(id) AND route_id = sqlc.arg(route_id);
