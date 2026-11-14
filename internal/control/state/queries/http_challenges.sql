-- name: CreateHTTPChallenge :one
INSERT INTO control.http_challenges (
    id, resource_kind, resource_id, hostname, port, browser_binding_hash,
    publisher_binding_hash, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(resource_kind), sqlc.arg(resource_id), sqlc.arg(hostname),
    sqlc.arg(port), sqlc.arg(browser_binding_hash), sqlc.arg(publisher_binding_hash),
    sqlc.arg(expires_at)
) RETURNING *;

-- name: GetHTTPChallenge :one
SELECT * FROM control.http_challenges WHERE id = sqlc.arg(id);

-- name: CountHTTPChallenges :one
SELECT count(*) FROM control.http_challenges
WHERE resource_kind = sqlc.arg(resource_kind) AND resource_id = sqlc.arg(resource_id);

-- name: PruneHTTPResourceChallenges :exec
DELETE FROM control.http_challenges
WHERE resource_kind = sqlc.arg(resource_kind) AND resource_id = sqlc.arg(resource_id)
  AND expires_at <= sqlc.arg(now)
  AND (handoff_expires_at IS NULL OR handoff_expires_at <= sqlc.arg(now));

-- name: ClaimHTTPChallenge :one
UPDATE control.http_challenges SET verification_started_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND browser_binding_hash = sqlc.arg(browser_binding_hash)
  AND expires_at > sqlc.arg(now) AND verification_started_at IS NULL
RETURNING *;

-- name: CompleteHTTPChallenge :execrows
UPDATE control.http_challenges
SET verified_at = sqlc.arg(now), handoff_hash = sqlc.arg(handoff_hash),
    handoff_expires_at = sqlc.arg(handoff_expires_at)
WHERE id = sqlc.arg(id) AND expires_at > sqlc.arg(now)
  AND verification_started_at IS NOT NULL AND verified_at IS NULL;

-- name: RedeemHTTPChallenge :one
UPDATE control.http_challenges SET redeemed_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND resource_kind = sqlc.arg(resource_kind)
  AND resource_id = sqlc.arg(resource_id) AND handoff_hash = sqlc.arg(handoff_hash)
  AND publisher_binding_hash = sqlc.arg(publisher_binding_hash)
  AND handoff_expires_at > sqlc.arg(now) AND verified_at IS NOT NULL AND redeemed_at IS NULL
RETURNING *;

-- name: PruneHTTPChallenges :exec
DELETE FROM control.http_challenges
WHERE id IN (
    SELECT expired.id FROM control.http_challenges expired
    WHERE expired.expires_at <= sqlc.arg(now)
      AND (expired.handoff_expires_at IS NULL OR expired.handoff_expires_at <= sqlc.arg(now))
    ORDER BY expired.expires_at LIMIT 1000
);
