-- name: GetDNSChallengeContext :one
SELECT
    routes.id AS route_id,
    routes.team_id,
    routes.domain_id,
    routes.dns_authority_reference,
    routes.canonical_hostname,
    domains.canonical_domain,
    authorizations.id AS authorization_id,
    authorizations.identifier,
    authorizations.challenge_digest,
    authorizations.presentation_reference,
    authorizations.state
FROM control.acme_authorizations AS authorizations
JOIN control.acme_orders AS orders ON orders.id = authorizations.order_id
JOIN control.routes AS routes ON routes.id = orders.route_id
JOIN control.domains AS domains ON domains.id = routes.domain_id
WHERE routes.id = sqlc.arg(route_id)
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
