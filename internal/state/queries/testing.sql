-- Test-only white-box queries shared by persistence tests.

-- name: CountPrincipals :one
SELECT COUNT(*) FROM principals;

-- name: CountPrincipalByID :one
SELECT COUNT(*) FROM principals WHERE id = sqlc.arg(id);

-- name: CountAccessCredentials :one
SELECT COUNT(*) FROM access_credentials;

-- name: GetOIDCAssertionExpiry :one
SELECT expires_at FROM oidc_assertion_exchanges LIMIT 1;

-- name: CountClaimRequestsByClaim :one
SELECT COUNT(*) FROM hostname_claim_requests WHERE claim_id = sqlc.arg(claim_id);

-- name: ClearACMEAccountKID :exec
UPDATE acme_accounts SET kid = NULL WHERE directory_url = sqlc.arg(directory_url);

-- name: SetACMEAccountEmail :exec
UPDATE acme_accounts SET email = sqlc.arg(email);

-- name: GetLatestRouteLeaseStatus :one
SELECT status
FROM route_leases
WHERE route_id = sqlc.arg(route_id)
ORDER BY generation DESC
LIMIT 1;

-- name: GetLatestCertificateJobState :one
SELECT state, installed_at, challenge_removed_at
FROM certificate_jobs
WHERE route_id = sqlc.arg(route_id)
ORDER BY generation DESC
LIMIT 1;

-- name: CountCertificateJobsByRoute :one
SELECT COUNT(*) FROM certificate_jobs WHERE route_id = sqlc.arg(route_id);

-- name: GetAnyACMEAccountKID :one
SELECT CAST(COALESCE(kid, '') AS TEXT) FROM acme_accounts LIMIT 1;

-- name: SetCertificateRenewalDue :execrows
UPDATE certificate_jobs
SET renew_at = CAST(sqlc.arg(renew_at) AS INTEGER)
WHERE id = sqlc.arg(id) AND route_id = sqlc.arg(route_id);
