-- name: GetDNSChallengeSubject :one
SELECT orders.service_id,orders.service_run_id,orders.service_run_number
FROM control.acme_orders AS orders
JOIN control.acme_authorizations AS authorizations ON authorizations.order_id = orders.id
WHERE authorizations.id = sqlc.arg(authorization_id)
  AND authorizations.challenge_type = 'dns-01'
  AND orders.service_id = sqlc.arg(owner_id);

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
