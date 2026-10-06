-- name: CreateInvitationEmail :exec
INSERT INTO control.email_deliveries(delivery_id, payload_ciphertext, storage_key_id, available_at)
VALUES (sqlc.arg(delivery_id), sqlc.arg(payload_ciphertext), sqlc.arg(storage_key_id), sqlc.arg(available_at));

-- name: DiscardInactiveInvitationEmails :exec
UPDATE control.email_deliveries AS delivery
SET completed_at = sqlc.arg(now), payload_ciphertext = NULL, storage_key_id = NULL,
    lease_owner = NULL, lease_expires_at = NULL
FROM control.team_invitations AS invitation
WHERE invitation.id = delivery.delivery_id AND delivery.completed_at IS NULL
  AND (invitation.state <> 'pending' OR invitation.expires_at <= sqlc.arg(now))
  AND (delivery.lease_owner IS NULL OR delivery.lease_expires_at <= sqlc.arg(now));

-- name: ClaimInvitationEmail :one
WITH candidate AS (
    SELECT delivery.delivery_id FROM control.email_deliveries AS delivery
    JOIN control.team_invitations AS invitation ON invitation.id = delivery.delivery_id
    WHERE delivery.completed_at IS NULL AND delivery.available_at <= sqlc.arg(now)
      AND (delivery.lease_owner IS NULL OR delivery.lease_expires_at <= sqlc.arg(now))
      AND invitation.state = 'pending' AND invitation.expires_at > sqlc.arg(now)
    ORDER BY delivery.available_at, delivery.delivery_id
    FOR UPDATE OF delivery SKIP LOCKED LIMIT 1
)
UPDATE control.email_deliveries AS delivery
SET lease_owner = sqlc.arg(lease_owner), lease_expires_at = sqlc.arg(lease_expires_at), attempts = attempts + 1
FROM candidate WHERE delivery.delivery_id = candidate.delivery_id
RETURNING delivery.*;

-- name: FinishInvitationEmail :execrows
UPDATE control.email_deliveries
SET completed_at = CASE WHEN sqlc.arg(complete)::boolean THEN sqlc.arg(now)::timestamptz ELSE NULL END,
    payload_ciphertext = CASE WHEN sqlc.arg(complete)::boolean THEN NULL ELSE payload_ciphertext END,
    storage_key_id = CASE WHEN sqlc.arg(complete)::boolean THEN NULL ELSE storage_key_id END,
    available_at = sqlc.arg(available_at), last_status = sqlc.arg(last_status),
    lease_owner = NULL, lease_expires_at = NULL
WHERE delivery_id = sqlc.arg(delivery_id) AND lease_owner = sqlc.arg(lease_owner)
  AND lease_expires_at > sqlc.arg(now) AND completed_at IS NULL;
