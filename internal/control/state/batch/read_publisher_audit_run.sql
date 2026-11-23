-- name: ReadPublisherAuditRun :one
SELECT r.team_id, r.guest_id, r.publisher_identity_id, r.protocol, r.created_at,
       LEAST(r.publisher_expires_at, r.closed_at, p.revoked_at, g.revoked_at, g.expires_at)
FROM control.service_runs r
JOIN control.publisher_identities p ON p.id = r.publisher_identity_id
    AND p.team_id IS NOT DISTINCT FROM r.team_id AND p.guest_id IS NOT DISTINCT FROM r.guest_id
JOIN control.publisher_grants g ON g.id = r.publisher_grant_id AND g.publisher_identity_id = p.id
WHERE r.service_id = $1 AND r.id = $2 AND r.run_number = $3 AND r.run_token_digest = $4
  AND r.ready_at IS NOT NULL;
