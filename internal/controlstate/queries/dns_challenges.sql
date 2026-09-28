-- name: GetDNSChallengeContext :one
SELECT
    routes.id AS public_url_id,
    routes.team_id,
    routes.domain_id,
    routes.dns_authority_reference,
    routes.canonical_hostname,
    COALESCE(authorities.canonical_domain, '')::text AS canonical_domain,
    authorizations.id AS authorization_id,
    authorizations.identifier,
    authorizations.challenge_digest,
    authorizations.presentation_reference,
    authorizations.state
FROM control.acme_authorizations AS authorizations
JOIN control.acme_orders AS orders ON orders.id = authorizations.order_id
JOIN control.public_urls AS routes ON routes.id = orders.public_url_id
LEFT JOIN control.dns_authorities AS authorities
    ON authorities.authority_reference = routes.dns_authority_reference
    AND authorities.team_id = routes.team_id
    AND authorities.domain_id = routes.domain_id
WHERE routes.id = sqlc.arg(public_url_id)
  AND authorizations.id = sqlc.arg(authorization_id)
  AND authorizations.challenge_type = 'dns-01';

-- name: ListDNSChallengePresentations :many
SELECT challenge_digest, state
FROM control.acme_authorizations
WHERE challenge_type = 'dns-01'
  AND CASE
      WHEN left(identifier, 2) = '*.' THEN substring(identifier FROM 3)
      ELSE identifier
  END = sqlc.arg(base_identifier)
ORDER BY id;

-- name: GetDNSChallengeChange :one
SELECT desired_digest, change_id
FROM control.dns_challenge_changes
WHERE zone_id = sqlc.arg(zone_id) AND record_name = sqlc.arg(record_name);

-- name: UpsertDNSChallengeChange :exec
INSERT INTO control.dns_challenge_changes (zone_id, record_name, desired_digest, change_id, updated_at)
VALUES (sqlc.arg(zone_id), sqlc.arg(record_name), sqlc.arg(desired_digest), sqlc.arg(change_id), sqlc.arg(updated_at))
ON CONFLICT (zone_id, record_name) DO UPDATE SET
    desired_digest = excluded.desired_digest,
    change_id = excluded.change_id,
    updated_at = excluded.updated_at;
